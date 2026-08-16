package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
	"github.com/kubewarden/gateway-protector/internal/controller"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
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
			var cfgMap corev1.ConfigMap
			err := wait.For(func(ctx context.Context) (bool, error) {
				if err := cfg.Client().Resources(namespace).Get(ctx, controller.ProcessorConfigMapName, namespace, &cfgMap); err != nil {
					return false, nil //nolint:nilerr // keep polling until the ConfigMap exists
				}

				return len(cfgMap.Data["config.yaml"]) > 0, nil
			}, wait.WithTimeout(statusTimeout))
			require.NoError(t, err, "processor ConfigMap %s/%s was never published", namespace, controller.ProcessorConfigMapName)

			var procCfg procconfig.Config
			err = yaml.Unmarshal([]byte(cfgMap.Data["config.yaml"]), &procCfg)
			require.NoError(t, err, "failed to parse published processor config")

			var httpbinRoute *procconfig.Route
			for i := range procCfg.Routes {
				if procCfg.Routes[i].Host == "*" {
					httpbinRoute = &procCfg.Routes[i]

					break
				}
			}
			require.NotNil(t, httpbinRoute, "expected a catch-all route in the published processor config")
			assert.NotNil(t, httpbinRoute.WAF, "expected the catch-all route to have a WAF engine attached")

			agwPolicy := &agentgatewayapi.AgentgatewayPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "gateway-protector-" + httpbinRouteName, Namespace: httpbinNamespace},
			}
			err = wait.For(
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
