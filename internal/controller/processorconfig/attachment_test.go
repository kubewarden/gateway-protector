package processorconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

func gatewayTargetRef(namespace, name string, section *gatewayv1.SectionName) gwpv1alpha1.PolicyTargetReference {
	return gwpv1alpha1.PolicyTargetReference{
		Group:       gatewayv1.GroupName,
		Kind:        "Gateway",
		Name:        gatewayv1.ObjectName(name),
		Namespace:   gatewayv1.Namespace(namespace),
		SectionName: section,
	}
}

func httpRouteTargetRef(name string, section *gatewayv1.SectionName) gwpv1alpha1.PolicyTargetReference {
	return gwpv1alpha1.PolicyTargetReference{
		Group:       gatewayv1.GroupName,
		Kind:        "HTTPRoute",
		Name:        gatewayv1.ObjectName(name),
		Namespace:   "team-shop",
		SectionName: section,
	}
}

func newPolicy(name string, targetRef gwpv1alpha1.PolicyTargetReference) *gwpv1alpha1.WAFPolicy {
	return &gwpv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "platform"},
		Spec:       gwpv1alpha1.WAFPolicySpec{TargetRef: targetRef},
	}
}

// shopRoute builds the "team-shop/shop" HTTPRoute with the given parentRefs
// and rules.
func shopRoute(parentRefs []gatewayv1.ParentReference, rules ...gatewayv1.HTTPRouteRule) *gatewayv1.HTTPRoute {
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parentRefs},
			Rules:           rules,
		},
	}
}

func infraParentRef(gateway string, section *gatewayv1.SectionName) gatewayv1.ParentReference {
	return gatewayv1.ParentReference{
		Name:        gatewayv1.ObjectName(gateway),
		Namespace:   new(gatewayv1.Namespace("infra")),
		SectionName: section,
	}
}

func namedRule(name string) gatewayv1.HTTPRouteRule {
	return gatewayv1.HTTPRouteRule{Name: new(gatewayv1.SectionName(name))}
}

func TestCandidatePolicies(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewayAdmin := newPolicy("gw-admin", gatewayTargetRef("infra", "shared-gw", new(gatewayv1.SectionName("admin"))))
	gatewayHTTP := newPolicy("gw-http", gatewayTargetRef("infra", "shared-gw", new(gatewayv1.SectionName("http"))))
	otherGatewayDefault := newPolicy("other-gw-default", gatewayTargetRef("infra", "other-gw", nil))
	routeDefault := newPolicy("route-default", httpRouteTargetRef("shop", nil))
	routeCheckout := newPolicy("route-checkout", httpRouteTargetRef("shop", new(gatewayv1.SectionName("checkout"))))
	routeHealth := newPolicy("route-health", httpRouteTargetRef("shop", new(gatewayv1.SectionName("health"))))

	sharedGateway := []gatewayv1.ParentReference{infraParentRef("shared-gw", nil)}

	tests := []struct {
		name     string
		policies []*gwpv1alpha1.WAFPolicy
		route    *gatewayv1.HTTPRoute
		want     []*gwpv1alpha1.WAFPolicy
	}{
		{
			name:     "rule policies and the route policy, never the gateway policies below them",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault, routeDefault, routeCheckout},
			route:    shopRoute(sharedGateway, namedRule("checkout"), namedRule("browse"), gatewayv1.HTTPRouteRule{}),
			want:     []*gwpv1alpha1.WAFPolicy{routeCheckout, routeDefault},
		},
		{
			name:     "rules that all have a policy of their own leave nothing to fall through",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault, routeDefault, routeCheckout, routeHealth},
			route:    shopRoute(sharedGateway, namedRule("checkout"), namedRule("health")),
			want:     []*gwpv1alpha1.WAFPolicy{routeCheckout, routeHealth},
		},
		{
			name:     "an unnamed rule falls through to the gateway",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault, routeHealth},
			route:    shopRoute(sharedGateway, namedRule("health"), gatewayv1.HTTPRouteRule{}),
			want:     []*gwpv1alpha1.WAFPolicy{routeHealth, gatewayDefault},
		},
		{
			name:     "a parentRef with a sectionName reaches only that listener's policy when it has one",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault, gatewayAdmin, gatewayHTTP},
			route:    shopRoute([]gatewayv1.ParentReference{infraParentRef("shared-gw", new(gatewayv1.SectionName("admin")))}, gatewayv1.HTTPRouteRule{}),
			want:     []*gwpv1alpha1.WAFPolicy{gatewayAdmin},
		},
		{
			name:     "a parentRef with a sectionName falls back to the gateway default",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault, gatewayHTTP},
			route:    shopRoute([]gatewayv1.ParentReference{infraParentRef("shared-gw", new(gatewayv1.SectionName("admin")))}, gatewayv1.HTTPRouteRule{}),
			want:     []*gwpv1alpha1.WAFPolicy{gatewayDefault},
		},
		{
			name:     "a parentRef without a sectionName reaches every listener policy and the gateway default",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault, gatewayHTTP, gatewayAdmin},
			route:    shopRoute(sharedGateway, gatewayv1.HTTPRouteRule{}),
			want:     []*gwpv1alpha1.WAFPolicy{gatewayAdmin, gatewayHTTP, gatewayDefault},
		},
		{
			name:     "a listener policy alone covers a route whose parentRef names no listener",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayHTTP},
			route:    shopRoute(sharedGateway, gatewayv1.HTTPRouteRule{}),
			want:     []*gwpv1alpha1.WAFPolicy{gatewayHTTP},
		},
		{
			name:     "every parent gateway's policy is a candidate, not only the first one's",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault, otherGatewayDefault},
			route: shopRoute([]gatewayv1.ParentReference{
				infraParentRef("shared-gw", nil),
				infraParentRef("other-gw", nil),
			}, gatewayv1.HTTPRouteRule{}),
			want: []*gwpv1alpha1.WAFPolicy{gatewayDefault, otherGatewayDefault},
		},
		{
			name:     "a gateway listed twice in parentRefs contributes its policy once",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault},
			route: shopRoute([]gatewayv1.ParentReference{
				infraParentRef("shared-gw", new(gatewayv1.SectionName("http"))),
				infraParentRef("shared-gw", new(gatewayv1.SectionName("admin"))),
			}, gatewayv1.HTTPRouteRule{}),
			want: []*gwpv1alpha1.WAFPolicy{gatewayDefault},
		},
		{
			name:     "a non-Gateway parentRef is skipped",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault},
			route: shopRoute([]gatewayv1.ParentReference{{
				Name:  "shared-gw",
				Kind:  new(gatewayv1.Kind("Service")),
				Group: new(gatewayv1.Group("")),
			}}, gatewayv1.HTTPRouteRule{}),
			want: nil,
		},
		{
			name:     "a route with no rules has no candidates",
			policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault, routeDefault},
			route:    shopRoute(sharedGateway),
			want:     nil,
		},
		{
			name:     "no policy at all",
			policies: nil,
			route:    shopRoute(sharedGateway, gatewayv1.HTTPRouteRule{}),
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := candidatePolicies(newPolicyIndex(tt.policies), tt.route)
			assert.Equal(t, sets.New(tt.want...), got)
		})
	}
}

func TestCandidatePoliciesParentRefNamespaceDefaultsToRouteNamespace(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("team-shop", "local-gw", nil))
	idx := newPolicyIndex([]*gwpv1alpha1.WAFPolicy{gatewayDefault})

	// No Namespace set: per the Gateway API spec, this defaults to the
	// route's own namespace.
	route := shopRoute([]gatewayv1.ParentReference{{Name: "local-gw"}}, gatewayv1.HTTPRouteRule{})

	assert.Equal(t, sets.New(gatewayDefault), candidatePolicies(idx, route))
}

func TestIsGatewayParentRef(t *testing.T) {
	assert.True(t, isGatewayParentRef(gatewayv1.ParentReference{Name: "gw"}), "unset Group/Kind default to Gateway")
	assert.True(t, isGatewayParentRef(gatewayv1.ParentReference{
		Name:  "gw",
		Group: new(gatewayv1.Group(gatewayv1.GroupName)),
		Kind:  new(gatewayv1.Kind("Gateway")),
	}))
	assert.False(t, isGatewayParentRef(gatewayv1.ParentReference{
		Name: "svc",
		Kind: new(gatewayv1.Kind("Service")),
	}))
}

func TestNewPolicyIndex(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewayHTTPS := newPolicy("gw-https", gatewayTargetRef("infra", "shared-gw", new(gatewayv1.SectionName("https"))))
	gatewayAdmin := newPolicy("gw-admin", gatewayTargetRef("infra", "shared-gw", new(gatewayv1.SectionName("admin"))))
	idx := newPolicyIndex([]*gwpv1alpha1.WAFPolicy{gatewayDefault, gatewayHTTPS, gatewayAdmin})

	got, ok := idx.lookup("Gateway", "infra", "shared-gw", "")
	require.True(t, ok)
	assert.Same(t, gatewayDefault, got)

	_, ok = idx.lookup("Gateway", "infra", "shared-gw", "http")
	assert.False(t, ok)

	assert.ElementsMatch(t, []*gwpv1alpha1.WAFPolicy{gatewayAdmin, gatewayHTTPS},
		idx.listenerPolicies[types.NamespacedName{Namespace: "infra", Name: "shared-gw"}],
		"listener policies are indexed per Gateway, without the gateway default")
}
