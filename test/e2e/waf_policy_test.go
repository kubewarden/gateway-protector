package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
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

const (
	// httpbinNamespace/httpbinGatewayName/httpbinRouteName/httpbinDeploymentName
	// mirror test/manifests/httpbin.yaml, shared with the Tiltfile.
	httpbinNamespace      = "httpbin"
	httpbinGatewayName    = "httpbin-gateway"
	httpbinRouteName      = "httpbin"
	httpbinDeploymentName = "httpbin"
	curlContainerName     = "curl"

	// wafPolicyName/wafPolicyNamespace: WAFPolicy objects live in the
	// controller's own namespace (see examples/wafpolicy-demo.yaml), while
	// they target the Gateway living in httpbinNamespace.
	wafPolicyName = "httpbin-e2e"

	// maliciousQuery is a classic reflected-XSS payload that OWASP CRS
	// flags at paranoia level 1 - the same one used in the Tiltfile's demo
	// instructions, percent-encoded: agentgateway's HTTP/1.1 front end
	// rejects raw "<"/">" in a request target with its own 400 before the
	// request ever reaches the processor, independently of any WAFPolicy,
	// so the literal (unencoded) form can never reach the WAF to be
	// blocked. Coraza/CRS decode percent-encoding before pattern matching,
	// so the encoded form still triggers the same rule.
	maliciousQuery = "?q=%3Cscript%3Ealert(1)%3C/script%3E"

	trafficTimeout = 2 * time.Minute
	statusTimeout  = 1 * time.Minute
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
			err := decoder.DecodeEachFile(ctx, os.DirFS("../manifests"), "httpbin.yaml",
				decoder.CreateHandler(cfg.Client().Resources()))
			require.NoError(t, err, "failed to apply test/manifests/httpbin.yaml")

			err = wait.For(
				conditions.New(cfg.Client().Resources()).DeploymentAvailable(httpbinDeploymentName, httpbinNamespace),
				wait.WithTimeout(trafficTimeout),
			)
			require.NoError(t, err, "httpbin Deployment never became Available")

			// agentgateway creates a Deployment (and Service) named after
			// the Gateway object, in the Gateway's own namespace, once it
			// has programmed the Gateway.
			err = wait.For(
				conditions.New(cfg.Client().Resources()).DeploymentAvailable(httpbinGatewayName, httpbinNamespace),
				wait.WithTimeout(trafficTimeout),
			)
			require.NoError(t, err, "agentgateway proxy Deployment %s/%s never became Available", httpbinNamespace, httpbinGatewayName)

			return ctx
		}).
		Assess("Traffic flows before any WAFPolicy exists", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, "/get", "200", trafficTimeout)

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
			waitForStatus(ctx, t, cfg, "/get"+maliciousQuery, "403", trafficTimeout)

			return ctx
		}).
		Assess("Benign request still succeeds", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, "/get", "200", statusTimeout)

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

			waitForStatus(ctx, t, cfg, "/get"+maliciousQuery, "200", trafficTimeout)

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

// curlStatus execs into httpbin's curl sidecar (kept around exactly for
// this purpose - see test/manifests/httpbin.yaml) and returns the HTTP
// status code a request through the agentgateway-managed proxy Service
// gets back.
func curlStatus(ctx context.Context, cfg *envconf.Config, path string) (string, error) {
	var stdout, stderr bytes.Buffer

	url := fmt.Sprintf("http://%s.%s/%s", httpbinGatewayName, httpbinNamespace, strings.TrimPrefix(path, "/"))
	cmd := []string{"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url}

	err := cfg.Client().Resources().ExecInDeployment(ctx, httpbinNamespace, httpbinDeploymentName, cmd, &stdout, &stderr,
		resources.WithDeploymentContainerName(curlContainerName))
	if err != nil {
		return "", fmt.Errorf("curl exec failed: %w (stderr: %s)", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

// waitForStatus polls curlStatus until it returns want or timeout elapses.
func waitForStatus(ctx context.Context, t *testing.T, cfg *envconf.Config, path, want string, timeout time.Duration) {
	t.Helper()

	var last string
	err := wait.For(func(ctx context.Context) (bool, error) {
		status, err := curlStatus(ctx, cfg, path)
		if err != nil {
			// The gateway/pod may not be reachable yet right after
			// creation - keep polling instead of failing fast.
			return false, nil //nolint:nilerr // transient exec error, keep polling until timeout
		}

		last = status

		return status == want, nil
	}, wait.WithTimeout(timeout), wait.WithInterval(5*time.Second), wait.WithContext(ctx))
	require.NoError(t, err, "timed out waiting for %s to return %s (last status observed: %q)", path, want, last)
}
