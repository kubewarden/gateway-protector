package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
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
)

const (
	selectionNamespace = "httpbin-selection"

	// selectionInternalGatewayName is a second Gateway in the namespace,
	// next to httpbinGatewayName, that serves the same hostnames.
	selectionInternalGatewayName = "httpbin-internal"

	selectionRouteName = "selection"
	selectionHost      = "selection.test"
	shopHost           = "shop.selection.test"
	sharedHost         = "shared.selection.test"
)

// selectionPolicies are the WAFPolicies of TestWAFPolicySelection: a
// Blocking default on httpbinGatewayName, an Off default on
// selectionInternalGatewayName, and two Off rule policies on the
// "selection" HTTPRoute.
var selectionPolicies = []struct {
	name    string
	kind    gatewayv1.Kind
	target  string
	section string
	mode    v1alpha1.WAFEngineMode
}{
	{name: "selection-gateway-blocking", kind: "Gateway", target: httpbinGatewayName, mode: v1alpha1.WAFEngineModeBlocking},
	{name: "selection-internal-off", kind: "Gateway", target: selectionInternalGatewayName, mode: v1alpha1.WAFEngineModeOff},
	{name: "selection-health-off", kind: "HTTPRoute", target: selectionRouteName, section: "health", mode: v1alpha1.WAFEngineModeOff},
	{name: "selection-beta-off", kind: "HTTPRoute", target: selectionRouteName, section: "beta", mode: v1alpha1.WAFEngineModeOff},
}

func selectionBackendRefs() []gatewayv1.HTTPBackendRef {
	return []gatewayv1.HTTPBackendRef{{
		BackendRef: gatewayv1.BackendRef{
			BackendObjectReference: gatewayv1.BackendObjectReference{
				Name: gatewayv1.ObjectName(httpbinDeploymentName),
				Port: ptr.To(gatewayv1.PortNumber(8000)),
			},
		},
	}}
}

func selectionPathPrefix(value string) *gatewayv1.HTTPPathMatch {
	return &gatewayv1.HTTPPathMatch{Type: ptr.To(gatewayv1.PathMatchPathPrefix), Value: new(value)}
}

// selectionCatchAllRoute is an HTTPRoute with one unnamed catch-all rule
// for host, attached to the given Gateways.
func selectionCatchAllRoute(name, host string, gateways ...string) *gatewayv1.HTTPRoute {
	parentRefs := make([]gatewayv1.ParentReference, len(gateways))
	for i, gateway := range gateways {
		parentRefs[i] = gatewayv1.ParentReference{Name: gatewayv1.ObjectName(gateway)}
	}

	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: selectionNamespace},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parentRefs},
			Hostnames:       []gatewayv1.Hostname{gatewayv1.Hostname(host)},
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches:     []gatewayv1.HTTPRouteMatch{{Path: selectionPathPrefix("/")}},
				BackendRefs: selectionBackendRefs(),
			}},
		},
	}
}

// TestWAFPolicySelection checks that the processor applies the policy of
// the route rule and the Gateway that agentgateway selects for a request,
// in the cases where an engine selection by host and path prefix picks
// the policy of another rule or Gateway:
//
//  1. A PathPrefix matches whole path segments: an Off policy on the rule
//     "PathPrefix /anything/health" does not cover /anything/healthz-admin.
//  2. A rule can match on more than the path: an Off policy on the rule
//     that also matches the header "x-beta: 1" does not cover the
//     requests without the header.
//  3. Two Gateways can serve the same hostname: the Blocking policy of one
//     Gateway applies to its traffic, the Off policy of the other to its
//     own - also for one HTTPRoute attached to both Gateways.
//
// go-httpbin serves every path under /anything, so a request that the
// WAF does not inspect gets 200, and a blocked one gets 403.
//
// e2e tests share a single Kind cluster managed by TestMain and mutate
// cluster-wide resources, so assessments below must run sequentially.
func TestWAFPolicySelection(t *testing.T) {
	f := features.New("WAFPolicy selection follows the route agentgateway selects").
		Assess("Deploy httpbin wired through agentgateway", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			deployHTTPBinBase(ctx, t, cfg, selectionNamespace)

			return ctx
		}).
		Assess("Create a second Gateway", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			gateway := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: selectionInternalGatewayName, Namespace: selectionNamespace},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "agentgateway",
					Listeners: []gatewayv1.Listener{{
						Name:     "http",
						Protocol: gatewayv1.HTTPProtocolType,
						Port:     80,
					}},
				},
			}
			require.NoError(t, cfg.Client().Resources().Create(ctx, gateway), "failed to create Gateway %s", selectionInternalGatewayName)

			err := wait.For(
				conditions.New(cfg.Client().Resources()).DeploymentAvailable(selectionInternalGatewayName, selectionNamespace),
				wait.WithTimeout(trafficTimeout),
			)
			require.NoError(t, err, "agentgateway proxy Deployment %s/%s never became Available", selectionNamespace, selectionInternalGatewayName)

			return ctx
		}).
		Assess("Create the HTTPRoutes", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			selection := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: selectionRouteName, Namespace: selectionNamespace},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(httpbinGatewayName)}},
					},
					Hostnames: []gatewayv1.Hostname{selectionHost},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Name:        ptr.To(gatewayv1.SectionName("health")),
							Matches:     []gatewayv1.HTTPRouteMatch{{Path: selectionPathPrefix("/anything/health")}},
							BackendRefs: selectionBackendRefs(),
						},
						{
							Name: ptr.To(gatewayv1.SectionName("beta")),
							Matches: []gatewayv1.HTTPRouteMatch{{
								Path:    selectionPathPrefix("/anything/api"),
								Headers: []gatewayv1.HTTPHeaderMatch{{Name: "x-beta", Value: "1"}},
							}},
							BackendRefs: selectionBackendRefs(),
						},
						{
							Matches:     []gatewayv1.HTTPRouteMatch{{Path: selectionPathPrefix("/")}},
							BackendRefs: selectionBackendRefs(),
						},
					},
				},
			}

			routes := []*gatewayv1.HTTPRoute{
				selection,
				selectionCatchAllRoute("shop-public", shopHost, httpbinGatewayName),
				selectionCatchAllRoute("shop-internal", shopHost, selectionInternalGatewayName),
				selectionCatchAllRoute("shared", sharedHost, httpbinGatewayName, selectionInternalGatewayName),
			}
			for _, route := range routes {
				require.NoError(t, cfg.Client().Resources().Create(ctx, route), "failed to create HTTPRoute %s", route.Name)
			}

			return ctx
		}).
		Assess("Create the WAFPolicies", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			for _, p := range selectionPolicies {
				policy := &v1alpha1.WAFPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: namespace},
					Spec: v1alpha1.WAFPolicySpec{
						TargetRef: v1alpha1.PolicyTargetReference{
							Group:     gatewayv1.GroupName,
							Kind:      p.kind,
							Name:      gatewayv1.ObjectName(p.target),
							Namespace: selectionNamespace,
						},
						Engine:        v1alpha1.WAFEngineSpec{Mode: p.mode},
						ParanoiaLevel: 1,
					},
				}
				if p.section != "" {
					policy.Spec.TargetRef.SectionName = new(gatewayv1.SectionName(p.section))
				}

				require.NoError(t, cfg.Client().Resources().Create(ctx, policy), "failed to create WAFPolicy %s", p.name)
			}

			return ctx
		}).
		Assess("All WAFPolicies become Accepted and Programmed", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			for _, p := range selectionPolicies {
				policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: namespace}}

				for _, conditionType := range []string{v1alpha1.ConditionTypeAccepted, v1alpha1.ConditionTypeProgrammed} {
					err := wait.For(
						conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
							wafPolicy, ok := obj.(*v1alpha1.WAFPolicy)
							return ok && apimeta.IsStatusConditionTrue(wafPolicy.Status.Conditions, conditionType)
						}),
						wait.WithTimeout(statusTimeout),
					)
					require.NoError(t, err, "WAFPolicy %s never became %s", p.name, conditionType)
				}
			}

			return ctx
		}).
		// Each case first waits for the blocked request: it proves that the
		// route is wired and the config is live, so the request that is
		// not inspected afterward is not inspected because of its policy.
		Assess("1. A path that only starts with the Off rule's prefix is blocked", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForRequestStatus(ctx, t, cfg, selectionNamespace,
				curlRequest{host: selectionHost, path: "/anything/healthz-admin" + maliciousQuery}, "403", trafficTimeout)
			waitForRequestStatus(ctx, t, cfg, selectionNamespace,
				curlRequest{host: selectionHost, path: "/anything/health/live" + maliciousQuery}, "200", trafficTimeout)

			return ctx
		}).
		Assess("2. A request without the Off rule's header is blocked", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForRequestStatus(ctx, t, cfg, selectionNamespace,
				curlRequest{host: selectionHost, path: "/anything/api/orders" + maliciousQuery}, "403", trafficTimeout)
			waitForRequestStatus(ctx, t, cfg, selectionNamespace,
				curlRequest{host: selectionHost, path: "/anything/api/orders" + maliciousQuery, headers: []string{"x-beta: 1"}}, "200", trafficTimeout)

			return ctx
		}).
		Assess("3. The traffic of the Blocking Gateway is blocked", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForRequestStatus(ctx, t, cfg, selectionNamespace,
				curlRequest{host: shopHost, path: "/anything/orders" + maliciousQuery}, "403", trafficTimeout)
			waitForRequestStatus(ctx, t, cfg, selectionNamespace,
				curlRequest{gateway: selectionInternalGatewayName, host: shopHost, path: "/anything/orders" + maliciousQuery}, "200", trafficTimeout)

			return ctx
		}).
		Assess("3. One HTTPRoute on two Gateways gets the policy of each Gateway", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForRequestStatus(ctx, t, cfg, selectionNamespace,
				curlRequest{host: sharedHost, path: "/anything/orders" + maliciousQuery}, "403", trafficTimeout)
			waitForRequestStatus(ctx, t, cfg, selectionNamespace,
				curlRequest{gateway: selectionInternalGatewayName, host: sharedHost, path: "/anything/orders" + maliciousQuery}, "200", trafficTimeout)

			return ctx
		}).
		Assess("Benign requests still succeed", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			for _, req := range []curlRequest{
				{host: selectionHost, path: "/anything/healthz-admin"},
				{host: selectionHost, path: "/anything/api/orders"},
				{host: shopHost, path: "/anything/orders"},
				{host: sharedHost, path: "/anything/orders"},
			} {
				waitForRequestStatus(ctx, t, cfg, selectionNamespace, req, "200", statusTimeout)
			}

			return ctx
		}).
		Teardown(func(ctx context.Context, _ *testing.T, cfg *envconf.Config) context.Context {
			nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: selectionNamespace}}
			_ = cfg.Client().Resources().Delete(ctx, nsObj)

			for _, p := range selectionPolicies {
				policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: namespace}}
				_ = cfg.Client().Resources().Delete(ctx, policy)
			}

			return ctx
		})

	testenv.Test(t, f.Feature())
}
