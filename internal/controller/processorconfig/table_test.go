package processorconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

func httpRouteTargetRef(namespace, name string, section *gatewayv1.SectionName) gwpv1alpha1.PolicyTargetReference {
	return gwpv1alpha1.PolicyTargetReference{
		Group:       gatewayv1.GroupName,
		Kind:        "HTTPRoute",
		Name:        gatewayv1.ObjectName(name),
		Namespace:   gatewayv1.Namespace(namespace),
		SectionName: section,
	}
}

func newPolicy(name string, targetRef gwpv1alpha1.PolicyTargetReference) *gwpv1alpha1.WAFPolicy {
	return &gwpv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "platform"},
		Spec:       gwpv1alpha1.WAFPolicySpec{TargetRef: targetRef},
	}
}

func TestEffectivePolicyForRule(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewaySection := newPolicy("gw-admin", gatewayTargetRef("infra", "shared-gw", new(gatewayv1.SectionName("admin"))))
	routeDefault := newPolicy("route-default", httpRouteTargetRef("team-shop", "shop", nil))
	routeRule := newPolicy("route-rule", httpRouteTargetRef("team-shop", "shop", new(gatewayv1.SectionName("checkout"))))

	idx := newPolicyIndex([]*gwpv1alpha1.WAFPolicy{gatewayDefault, gatewaySection, routeDefault, routeRule})

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "shared-gw", Namespace: new(gatewayv1.Namespace("infra"))},
				},
			},
		},
	}

	tests := []struct {
		name     string
		rule     gatewayv1.HTTPRouteRule
		expected *gwpv1alpha1.WAFPolicy
	}{
		{
			name:     "rule-specific route policy wins",
			rule:     gatewayv1.HTTPRouteRule{Name: new(gatewayv1.SectionName("checkout"))},
			expected: routeRule,
		},
		{
			name:     "whole-route policy applies to other rules",
			rule:     gatewayv1.HTTPRouteRule{Name: new(gatewayv1.SectionName("browse"))},
			expected: routeDefault,
		},
		{
			name:     "unnamed rule falls back to whole-route policy",
			rule:     gatewayv1.HTTPRouteRule{},
			expected: routeDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectivePolicyForRule(idx, route, &tt.rule)
			assert.Same(t, tt.expected, got)
		})
	}
}

func TestEffectivePolicyForRuleFallsBackToGateway(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewaySection := newPolicy("gw-admin", gatewayTargetRef("infra", "shared-gw", new(gatewayv1.SectionName("admin"))))

	idx := newPolicyIndex([]*gwpv1alpha1.WAFPolicy{gatewayDefault, gatewaySection})

	routeViaAdminListener := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "admin-portal", Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:        "shared-gw",
						Namespace:   new(gatewayv1.Namespace("infra")),
						SectionName: new(gatewayv1.SectionName("admin")),
					},
				},
			},
		},
	}

	got := effectivePolicyForRule(idx, routeViaAdminListener, &gatewayv1.HTTPRouteRule{})
	assert.Same(t, gatewaySection, got, "the listener-scoped policy should win over the gateway-wide default")

	routeViaDefaultListener := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "public-page", Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "shared-gw", Namespace: new(gatewayv1.Namespace("infra"))},
				},
			},
		},
	}

	got = effectivePolicyForRule(idx, routeViaDefaultListener, &gatewayv1.HTTPRouteRule{})
	assert.Same(t, gatewayDefault, got)
}

func TestEffectivePolicyForRuleNoMatch(t *testing.T) {
	idx := newPolicyIndex(nil)

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: "team-shop"},
	}

	got := effectivePolicyForRule(idx, route, &gatewayv1.HTTPRouteRule{})
	assert.Nil(t, got)
}

func TestEffectivePolicyForRuleNamespaceDefaultsToRouteNamespace(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("team-shop", "local-gw", nil))
	idx := newPolicyIndex([]*gwpv1alpha1.WAFPolicy{gatewayDefault})

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				// No Namespace set: per the Gateway API spec, this defaults
				// to the route's own namespace.
				ParentRefs: []gatewayv1.ParentReference{{Name: "local-gw"}},
			},
		},
	}

	got := effectivePolicyForRule(idx, route, &gatewayv1.HTTPRouteRule{})
	assert.Same(t, gatewayDefault, got)
}

func TestRouteHostsExplicitHostnames(t *testing.T) {
	route := &gatewayv1.HTTPRoute{
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"shop.example.com", "www.example.com"},
		},
	}

	hosts := routeHosts(route, nil)
	assert.Equal(t, []string{"shop.example.com", "www.example.com"}, hosts)
}

func TestRouteHostsFallsBackToListenerSectionName(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-gw", Namespace: "infra"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Hostname: new(gatewayv1.Hostname("http.example.com"))},
				{Name: "admin", Hostname: new(gatewayv1.Hostname("admin.example.com"))},
			},
		},
	}
	gateways := map[types.NamespacedName]*gatewayv1.Gateway{{Namespace: "infra", Name: "shared-gw"}: gw}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:        "shared-gw",
						Namespace:   new(gatewayv1.Namespace("infra")),
						SectionName: new(gatewayv1.SectionName("admin")),
					},
				},
			},
		},
	}

	assert.Equal(t, []string{"admin.example.com"}, routeHosts(route, gateways))
}

func TestRouteHostsFallsBackToSingleListenerGateway(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-gw", Namespace: "infra"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Hostname: new(gatewayv1.Hostname("shop.example.com"))},
			},
		},
	}
	gateways := map[types.NamespacedName]*gatewayv1.Gateway{{Namespace: "infra", Name: "shared-gw"}: gw}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "shared-gw", Namespace: new(gatewayv1.Namespace("infra"))},
				},
			},
		},
	}

	assert.Equal(t, []string{"shop.example.com"}, routeHosts(route, gateways))
}

func TestRouteHostsFallsBackToCatchAll(t *testing.T) {
	tests := []struct {
		name     string
		route    *gatewayv1.HTTPRoute
		gateways map[types.NamespacedName]*gatewayv1.Gateway
	}{
		{
			name:     "no parentRefs at all",
			route:    &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "team-shop"}},
			gateways: nil,
		},
		{
			name: "multi-listener gateway with no sectionName to disambiguate",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Namespace: "team-shop"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "shared-gw", Namespace: new(gatewayv1.Namespace("infra"))},
						},
					},
				},
			},
			gateways: map[types.NamespacedName]*gatewayv1.Gateway{
				{Namespace: "infra", Name: "shared-gw"}: {
					ObjectMeta: metav1.ObjectMeta{Name: "shared-gw", Namespace: "infra"},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{
							{Name: "http"},
							{Name: "https"},
						},
					},
				},
			},
		},
		{
			name: "listener has no hostname set",
			route: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Namespace: "team-shop"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "shared-gw", Namespace: new(gatewayv1.Namespace("infra"))},
						},
					},
				},
			},
			gateways: map[types.NamespacedName]*gatewayv1.Gateway{
				{Namespace: "infra", Name: "shared-gw"}: {
					ObjectMeta: metav1.ObjectMeta{Name: "shared-gw", Namespace: "infra"},
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{{Name: "http"}},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, []string{"*"}, routeHosts(tt.route, tt.gateways))
		})
	}
}

func TestRulePaths(t *testing.T) {
	tests := []struct {
		name string
		rule gatewayv1.HTTPRouteRule
		want []string
	}{
		{
			name: "no matches at all defaults to /",
			rule: gatewayv1.HTTPRouteRule{},
			want: []string{"/"},
		},
		{
			name: "match with no path defaults to /",
			rule: gatewayv1.HTTPRouteRule{Matches: []gatewayv1.HTTPRouteMatch{{}}},
			want: []string{"/"},
		},
		{
			name: "prefix match value is used",
			rule: gatewayv1.HTTPRouteRule{
				Matches: []gatewayv1.HTTPRouteMatch{
					{Path: &gatewayv1.HTTPPathMatch{Type: new(gatewayv1.PathMatchPathPrefix), Value: new("/api")}},
				},
			},
			want: []string{"/api"},
		},
		{
			name: "exact match value is used",
			rule: gatewayv1.HTTPRouteRule{
				Matches: []gatewayv1.HTTPRouteMatch{
					{Path: &gatewayv1.HTTPPathMatch{Type: new(gatewayv1.PathMatchExact), Value: new("/health")}},
				},
			},
			want: []string{"/health"},
		},
		{
			name: "multiple matches produce multiple paths",
			rule: gatewayv1.HTTPRouteRule{
				Matches: []gatewayv1.HTTPRouteMatch{
					{Path: &gatewayv1.HTTPPathMatch{Value: new("/api")}},
					{Path: &gatewayv1.HTTPPathMatch{Value: new("/admin")}},
				},
			},
			want: []string{"/api", "/admin"},
		},
		{
			name: "regular expression matches are skipped",
			rule: gatewayv1.HTTPRouteRule{
				Matches: []gatewayv1.HTTPRouteMatch{
					{Path: &gatewayv1.HTTPPathMatch{Type: new(gatewayv1.PathMatchRegularExpression), Value: new("^/api/.*$")}},
					{Path: &gatewayv1.HTTPPathMatch{Value: new("/admin")}},
				},
			},
			want: []string{"/admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rulePaths(&tt.rule))
		})
	}
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

func TestNewPolicyIndexRequiresUniqueAttachmentPoints(t *testing.T) {
	policy := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	idx := newPolicyIndex([]*gwpv1alpha1.WAFPolicy{policy})

	got, ok := idx.lookup("Gateway", "infra", "shared-gw", "")
	require.True(t, ok)
	assert.Same(t, policy, got)

	_, ok = idx.lookup("Gateway", "infra", "shared-gw", "admin")
	assert.False(t, ok)
}
