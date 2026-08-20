package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kubewarden/gateway-protector/api/v1alpha1"
	"github.com/kubewarden/gateway-protector/internal/agentgatewayapi"
)

// httpbinNamespace/wafPolicyName: TestWAFPolicyGatewayLifecycle is the one
// test that uses test/manifests/httpbin.yaml's own hardcoded namespace
// directly (matching the Tiltfile's demo instructions verbatim), rather
// than deployHTTPBinBase's isolated-namespace-per-test pattern. WAFPolicy
// objects live in the controller's own namespace (see
// examples/wafpolicy-demo.yaml), while they target the Gateway living in
// httpbinNamespace.
const (
	httpbinNamespace = "httpbin"
	wafPolicyName    = "httpbin-e2e"
)

// TestWAFPolicyGatewayLifecycle exercises the full loop the Tiltfile demo
// documents: attaching a Blocking-mode WAFPolicy to a Gateway makes
// agentgateway start routing that Gateway's traffic through the processor,
// which then blocks requests OWASP CRS flags while letting benign ones
// through - and removing the WAFPolicy restores unprotected traffic.
//
// e2e tests share a single Kind cluster managed by TestMain and mutate
// cluster-wide resources, so assessments below must run sequentially.
func TestWAFPolicyGatewayLifecycle(t *testing.T) {
	f := features.New("Gateway-attached WAFPolicy lifecycle").
		Assess("Deploy httpbin wired through agentgateway", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			deployHTTPBinBase(ctx, t, cfg, httpbinNamespace)

			return ctx
		}).
		Assess("Traffic flows before any WAFPolicy exists", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, httpbinNamespace, "", "/get", "200", trafficTimeout)

			return ctx
		}).
		Assess("Create a Gateway-attached WAFPolicy", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := &v1alpha1.WAFPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wafPolicyName,
					Namespace: namespace,
				},
				Spec: v1alpha1.WAFPolicySpec{
					TargetRef: v1alpha1.PolicyTargetReference{
						Group:     gatewayv1.GroupName,
						Kind:      "Gateway",
						Name:      httpbinGatewayName,
						Namespace: httpbinNamespace,
					},
					Engine:        v1alpha1.WAFEngineSpec{Mode: v1alpha1.WAFEngineModeBlocking},
					ParanoiaLevel: 1,
				},
			}
			err := cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err, "failed to create WAFPolicy")

			return ctx
		}).
		Assess("WAFPolicy becomes Accepted and Programmed", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: wafPolicyName, Namespace: namespace}}

			err := wait.For(
				conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
					p, ok := obj.(*v1alpha1.WAFPolicy)
					return ok && apimeta.IsStatusConditionTrue(p.Status.Conditions, v1alpha1.ConditionTypeAccepted)
				}),
				wait.WithTimeout(statusTimeout),
			)
			require.NoError(t, err, "WAFPolicy never became Accepted")

			err = wait.For(
				conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
					p, ok := obj.(*v1alpha1.WAFPolicy)
					return ok && apimeta.IsStatusConditionTrue(p.Status.Conditions, v1alpha1.ConditionTypeProgrammed)
				}),
				wait.WithTimeout(statusTimeout),
			)
			require.NoError(t, err, "WAFPolicy never became Programmed")

			return ctx
		}).
		Assess("Controller publishes processor config and AgentgatewayPolicy wiring", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// The processor config itself (engines + routing table) is
			// pushed to processor replicas directly over the gRPC config
			// stream (see docs/processor.md's "Config stream" section),
			// not exposed through the Kubernetes API. Whether the
			// controller actually published a WAF-engine route for this
			// Gateway is asserted behaviorally instead, by the "Malicious
			// request is blocked"/"Benign request still succeeds" steps
			// below.
			agwPolicy := &agentgatewayapi.AgentgatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "gateway-protector-" + httpbinRouteName, Namespace: httpbinNamespace},
			}
			err := wait.For(
				conditions.New(cfg.Client().Resources()).ResourceMatch(agwPolicy, func(obj k8s.Object) bool {
					_, ok := obj.(*agentgatewayapi.AgentgatewayPolicy)

					return ok
				}),
				wait.WithTimeout(statusTimeout),
			)
			require.NoError(t, err, "generated AgentgatewayPolicy for the httpbin HTTPRoute was never created")
			require.Len(t, agwPolicy.Spec.TargetRefs, 1)
			assert.Equal(t, httpbinRouteName, string(agwPolicy.Spec.TargetRefs[0].Name))

			return ctx
		}).
		Assess("Malicious request is blocked", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, httpbinNamespace, "", "/get"+maliciousQuery, "403", trafficTimeout)

			return ctx
		}).
		Assess("Benign request still succeeds", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, httpbinNamespace, "", "/get", "200", statusTimeout)

			return ctx
		}).
		Assess("Request and response bodies survive the WAF round trip", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Regression check for a failure mode entirely invisible to
			// every status-code-only assertion above: agentgateway's
			// FULL_DUPLEX_STREAMED ext_proc mode rebuilds both the
			// request body (before it reaches httpbin) and the response
			// body (before it reaches the client) exclusively from the
			// chunks the processor echoes back. A processor that stopped
			// echoing, or never released chunks withheld pending a WAF
			// verdict, still answers every ext_proc message correctly and
			// every status code above would stay green - the body itself
			// would just be silently truncated to nothing. See
			// waitForPostBodyEcho and test/coraza-e2e for where this was
			// first caught.
			//
			// The payload is padded past a single ext_proc chunk so the
			// multi-chunk hold/release path (not just a single-message
			// shortcut) is exercised on the request side. Content-Type:
			// application/json means the *request* body is inspectable
			// under @coraza.conf-recommended's default
			// SecRequestBodyAccess On (held/released), while the
			// *response* (also JSON - go-httpbin always replies as such)
			// is outside the default SecResponseBodyMimeType allowlist
			// (text/plain, text/html, text/xml) and so streams through
			// the plain per-chunk echo path instead - between the two,
			// this one request exercises both body-handling paths.
			body := fmt.Sprintf(`{"message":"hello waf","padding":"%s"}`, strings.Repeat("a", 32*1024))

			waitForPostBodyEcho(ctx, t, cfg, httpbinNamespace, "/anything", "application/json", body, trafficTimeout)

			return ctx
		}).
		Assess("Deleting the WAFPolicy stops enforcement", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: wafPolicyName, Namespace: namespace}}
			err := cfg.Client().Resources().Delete(ctx, policy)
			require.NoError(t, err, "failed to delete WAFPolicy")

			err = wait.For(
				conditions.New(cfg.Client().Resources()).ResourceDeleted(
					&agentgatewayapi.AgentgatewayPolicy{ObjectMeta: metav1.ObjectMeta{Name: "gateway-protector-" + httpbinRouteName, Namespace: httpbinNamespace}},
				),
				wait.WithTimeout(statusTimeout),
			)
			require.NoError(t, err, "generated AgentgatewayPolicy was not garbage collected after WAFPolicy deletion")

			waitForStatus(ctx, t, cfg, httpbinNamespace, "", "/get"+maliciousQuery, "200", trafficTimeout)

			return ctx
		}).
		Teardown(func(ctx context.Context, _ *testing.T, cfg *envconf.Config) context.Context {
			nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: httpbinNamespace}}
			_ = cfg.Client().Resources().Delete(ctx, nsObj)

			policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: wafPolicyName, Namespace: namespace}}
			_ = cfg.Client().Resources().Delete(ctx, policy)

			return ctx
		})

	testenv.Test(t, f.Feature())
}
