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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kubewarden/gateway-protector/api/v1alpha1"
	"github.com/kubewarden/gateway-protector/internal/controller"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

const (
	routeOverrideNamespace = "httpbin-override"
	routeOverrideHost      = "admin.httpbin-override.test"
	routeOverrideRouteName = "httpbin-admin"

	routeOverrideGatewayPolicyName = "route-override-gateway-default"
	routeOverrideRoutePolicyName   = "route-override-route-default"
	routeOverrideRulePolicyName    = "route-override-rule-get"
)

// TestWAFPolicyRouteOverride exercises WAFPolicy's most-specific-wins
// attachment precedence (see docs/policy-attachment.md) across three of
// its four levels, using a second HTTPRoute (httpbin-admin, distinguished
// from the base catch-all HTTPRoute by hostname so both can share the same
// httpbin backend without any path-rewrite) that has two named rules:
//
//   - Gateway "httpbin-gateway" (no sectionName, level 4 - least specific):
//     mode Detection - the default for every route attached to the
//     Gateway that no more specific policy covers.
//   - HTTPRoute "httpbin-admin" (no sectionName, level 2): mode Blocking -
//     replaces the Gateway default for this route as a whole.
//   - HTTPRoute "httpbin-admin" + sectionName "get" (level 1 - most
//     specific): mode Off - replaces the route's own default for that one
//     rule only.
//
// Level 3 (Gateway + listener sectionName) is already covered by
// wafpolicy_controller_test.go's envtest suite and isn't repeated here.
//
// e2e tests share a single Kind cluster managed by TestMain and mutate
// cluster-wide resources, so assessments below must run sequentially.
func TestWAFPolicyRouteOverride(t *testing.T) {
	f := features.New("HTTPRoute override (most-specific-wins)").
		Assess("Deploy httpbin wired through agentgateway", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			deployHTTPBinBase(ctx, t, cfg, routeOverrideNamespace)

			return ctx
		}).
		Assess("Create a second HTTPRoute with two named rules", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routeOverrideRouteName,
					Namespace: routeOverrideNamespace,
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(httpbinGatewayName)}},
					},
					Hostnames: []gatewayv1.Hostname{gatewayv1.Hostname(routeOverrideHost)},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Name: ptr.To(gatewayv1.SectionName("get")),
							Matches: []gatewayv1.HTTPRouteMatch{{
								Path: &gatewayv1.HTTPPathMatch{
									Type:  ptr.To(gatewayv1.PathMatchExact),
									Value: new("/get"),
								},
							}},
							BackendRefs: []gatewayv1.HTTPBackendRef{{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: gatewayv1.ObjectName(httpbinDeploymentName),
										Port: ptr.To(gatewayv1.PortNumber(8000)),
									},
								},
							}},
						},
						{
							Name: ptr.To(gatewayv1.SectionName("status")),
							Matches: []gatewayv1.HTTPRouteMatch{{
								Path: &gatewayv1.HTTPPathMatch{
									Type:  ptr.To(gatewayv1.PathMatchPathPrefix),
									Value: new("/status"),
								},
							}},
							BackendRefs: []gatewayv1.HTTPBackendRef{{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: gatewayv1.ObjectName(httpbinDeploymentName),
										Port: ptr.To(gatewayv1.PortNumber(8000)),
									},
								},
							}},
						},
					},
				},
			}
			err := cfg.Client().Resources().Create(ctx, route)
			require.NoError(t, err, "failed to create HTTPRoute %s", routeOverrideRouteName)

			return ctx
		}).
		Assess("Create Gateway-default, Route-default, and rule-specific WAFPolicies", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policies := []*v1alpha1.WAFPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: routeOverrideGatewayPolicyName, Namespace: namespace},
					Spec: v1alpha1.WAFPolicySpec{
						TargetRef: v1alpha1.PolicyTargetReference{
							Group:     gatewayv1.GroupName,
							Kind:      "Gateway",
							Name:      httpbinGatewayName,
							Namespace: routeOverrideNamespace,
						},
						Engine:        v1alpha1.WAFEngineSpec{Mode: v1alpha1.WAFEngineModeDetection},
						ParanoiaLevel: 1,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: routeOverrideRoutePolicyName, Namespace: namespace},
					Spec: v1alpha1.WAFPolicySpec{
						TargetRef: v1alpha1.PolicyTargetReference{
							Group:     gatewayv1.GroupName,
							Kind:      "HTTPRoute",
							Name:      routeOverrideRouteName,
							Namespace: routeOverrideNamespace,
						},
						Engine:        v1alpha1.WAFEngineSpec{Mode: v1alpha1.WAFEngineModeBlocking},
						ParanoiaLevel: 1,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: routeOverrideRulePolicyName, Namespace: namespace},
					Spec: v1alpha1.WAFPolicySpec{
						TargetRef: v1alpha1.PolicyTargetReference{
							Group:       gatewayv1.GroupName,
							Kind:        "HTTPRoute",
							Name:        routeOverrideRouteName,
							Namespace:   routeOverrideNamespace,
							SectionName: ptr.To(gatewayv1.SectionName("get")),
						},
						Engine:        v1alpha1.WAFEngineSpec{Mode: v1alpha1.WAFEngineModeOff},
						ParanoiaLevel: 1,
					},
				},
			}
			for _, policy := range policies {
				err := cfg.Client().Resources().Create(ctx, policy)
				require.NoError(t, err, "failed to create WAFPolicy %s", policy.Name)
			}

			return ctx
		}).
		Assess("All three WAFPolicies become Accepted and Programmed", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			for _, name := range []string{routeOverrideGatewayPolicyName, routeOverrideRoutePolicyName, routeOverrideRulePolicyName} {
				policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}

				err := wait.For(
					conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
						p, ok := obj.(*v1alpha1.WAFPolicy)
						return ok && apimeta.IsStatusConditionTrue(p.Status.Conditions, v1alpha1.ConditionTypeAccepted)
					}),
					wait.WithTimeout(statusTimeout),
				)
				require.NoError(t, err, "WAFPolicy %s never became Accepted", name)

				err = wait.For(
					conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
						p, ok := obj.(*v1alpha1.WAFPolicy)
						return ok && apimeta.IsStatusConditionTrue(p.Status.Conditions, v1alpha1.ConditionTypeProgrammed)
					}),
					wait.WithTimeout(statusTimeout),
				)
				require.NoError(t, err, "WAFPolicy %s never became Programmed", name)
			}

			return ctx
		}).
		Assess("Processor config's routing table reflects three distinct engines", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var cfgMap corev1.ConfigMap
			err := wait.For(func(ctx context.Context) (bool, error) {
				if err := cfg.Client().Resources(namespace).Get(ctx, controller.ProcessorConfigMapName, namespace, &cfgMap); err != nil {
					return false, nil //nolint:nilerr // keep polling until the ConfigMap exists
				}

				return len(cfgMap.Data["config.yaml"]) > 0, nil
			}, wait.WithTimeout(statusTimeout))
			require.NoError(t, err, "processor ConfigMap was never published")

			var procCfg procconfig.Config
			err = yaml.Unmarshal([]byte(cfgMap.Data["config.yaml"]), &procCfg)
			require.NoError(t, err, "failed to parse published processor config")

			findRoute := func(host, pathPrefix string) *procconfig.Route {
				for i := range procCfg.Routes {
					if procCfg.Routes[i].Host == host && procCfg.Routes[i].PathPrefix == pathPrefix {
						return &procCfg.Routes[i]
					}
				}

				return nil
			}

			catchAll := findRoute("*", "/")
			ruleGet := findRoute(routeOverrideHost, "/get")
			ruleStatus := findRoute(routeOverrideHost, "/status")

			require.NotNil(t, catchAll, "expected a catch-all route entry")
			require.NotNil(t, ruleGet, "expected a %s/get route entry", routeOverrideHost)
			require.NotNil(t, ruleStatus, "expected a %s/status route entry", routeOverrideHost)

			require.NotNil(t, catchAll.WAF, "catch-all route should have a WAF engine (Gateway-default Detection)")
			require.NotNil(t, ruleGet.WAF, "get rule should have a WAF engine (rule-specific Off)")
			require.NotNil(t, ruleStatus.WAF, "status rule should have a WAF engine (route-default Blocking)")

			assert.NotEqual(t, catchAll.WAF.EngineKey, ruleGet.WAF.EngineKey,
				"Gateway-default and rule-specific engines should differ (Detection vs Off)")
			assert.NotEqual(t, catchAll.WAF.EngineKey, ruleStatus.WAF.EngineKey,
				"Gateway-default and route-default engines should differ (Detection vs Blocking)")
			assert.NotEqual(t, ruleGet.WAF.EngineKey, ruleStatus.WAF.EngineKey,
				"rule-specific and route-default engines should differ (Off vs Blocking)")

			return ctx
		}).
		Assess("Catch-all route only detects (Gateway default)", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, routeOverrideNamespace, "", "/get"+maliciousQuery, "200", trafficTimeout)

			return ctx
		}).
		Assess("The 'get' rule is unprotected (most-specific Off wins over the route's own Blocking default)", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, routeOverrideNamespace, routeOverrideHost, "/get"+maliciousQuery, "200", trafficTimeout)

			return ctx
		}).
		Assess("The 'status' rule is blocked (falls through to the route's Blocking default)", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, routeOverrideNamespace, routeOverrideHost, "/status/200"+maliciousQuery, "403", trafficTimeout)

			return ctx
		}).
		Assess("Benign requests still succeed on every rule", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, routeOverrideNamespace, "", "/get", "200", statusTimeout)
			waitForStatus(ctx, t, cfg, routeOverrideNamespace, routeOverrideHost, "/get", "200", statusTimeout)
			waitForStatus(ctx, t, cfg, routeOverrideNamespace, routeOverrideHost, "/status/200", "200", statusTimeout)

			return ctx
		}).
		Teardown(func(ctx context.Context, _ *testing.T, cfg *envconf.Config) context.Context {
			nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: routeOverrideNamespace}}
			_ = cfg.Client().Resources().Delete(ctx, nsObj)

			for _, name := range []string{routeOverrideGatewayPolicyName, routeOverrideRoutePolicyName, routeOverrideRulePolicyName} {
				policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
				_ = cfg.Client().Resources().Delete(ctx, policy)
			}

			return ctx
		})

	testenv.Test(t, f.Feature())
}
