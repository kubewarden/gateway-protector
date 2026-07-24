package processorconfig

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// wiringTestRoute builds the "team-shop/shop" HTTPRoute attached to the
// named "infra"-namespace gateway with one unnamed rule, for
// wiring-focused Build tests.
func wiringTestRoute(gatewayName string) *gatewayv1.HTTPRoute {
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: gatewayv1.ObjectName(gatewayName), Namespace: new(gatewayv1.Namespace("infra"))},
				},
			},
			Hostnames: []gatewayv1.Hostname{"shop.example.com"},
			Rules:     []gatewayv1.HTTPRouteRule{{}},
		},
	}
}

func TestBuildWiringCoversProtectedRoute(t *testing.T) {
	policy := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	policy.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	route := wiringTestRoute("shared-gw")

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{policy},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, alwaysCompiles)

	wiring := result.Wiring

	require.Len(t, wiring, 1)
	assert.Same(t, route, wiring[0].Route)
	// A nil requestBody/responseBody spec means the Core Rule Set's
	// recommended defaults apply, and those enable both body phases.
	assert.True(t, wiring[0].NeedRequestBody)
	assert.True(t, wiring[0].NeedResponseBody)
}

func TestBuildWiringSkipsUncoveredRoute(t *testing.T) {
	policy := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	policy.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	route := wiringTestRoute("other-gw")

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{policy},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, alwaysCompiles)

	wiring := result.Wiring

	assert.Empty(t, wiring, "a route no policy covers needs no wiring")
}

func TestBuildWiringSkipsRouteCoveredOnlyByFailingPolicy(t *testing.T) {
	policy := newPolicy("broken", gatewayTargetRef("infra", "shared-gw", nil))
	policy.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	route := wiringTestRoute("shared-gw")

	failingCompile := func(string, string) error { return errors.New("boom") }

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{policy},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, failingCompile)

	wiring := result.Wiring

	assert.Empty(t, wiring, "a route whose only policy failed to compile must not be wired")
}

func TestBuildWiringBodyNeedsFollowInspectionSpecs(t *testing.T) {
	policy := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	policy.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking
	policy.Spec.RequestBody = &gwpv1alpha1.WAFBodyInspectionSpec{Enabled: false}
	policy.Spec.ResponseBody = &gwpv1alpha1.WAFBodyInspectionSpec{Enabled: false}

	route := wiringTestRoute("shared-gw")

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{policy},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, alwaysCompiles)

	wiring := result.Wiring

	require.Len(t, wiring, 1)
	assert.False(t, wiring[0].NeedRequestBody)
	assert.False(t, wiring[0].NeedResponseBody)
}

func TestBuildWiringOffRouteIsStillWiredWithoutBodies(t *testing.T) {
	policy := newPolicy("route-off", httpRouteTargetRef("shop", nil))
	policy.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeOff

	route := wiringTestRoute("shared-gw")

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{policy},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, alwaysCompiles)

	wiring := result.Wiring

	require.Len(t, wiring, 1, "an opt-out route still gets wired so its explicit off engine is reachable")
	assert.False(t, wiring[0].NeedRequestBody)
	assert.False(t, wiring[0].NeedResponseBody)
}

func TestBuildWiringUnionsBodyNeedsAcrossRules(t *testing.T) {
	// Rule "api" is covered by a rule-level policy with body inspection
	// off; the rest of the route falls back to the gateway default, whose
	// nil body specs mean the CRS-recommended "on". The route's single
	// wiring must carry the union: bodies needed.
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewayDefault.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	ruleOverride := newPolicy("rule-override", httpRouteTargetRef("shop", new(gatewayv1.SectionName("api"))))
	ruleOverride.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking
	ruleOverride.Spec.RequestBody = &gwpv1alpha1.WAFBodyInspectionSpec{Enabled: false}
	ruleOverride.Spec.ResponseBody = &gwpv1alpha1.WAFBodyInspectionSpec{Enabled: false}

	route := wiringTestRoute("shared-gw")
	route.Spec.Rules = []gatewayv1.HTTPRouteRule{
		{Name: new(gatewayv1.SectionName("api"))},
		{},
	}

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{gatewayDefault, ruleOverride},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, alwaysCompiles)

	wiring := result.Wiring

	require.Len(t, wiring, 1, "one wiring per route, not per rule")
	assert.True(t, wiring[0].NeedRequestBody)
	assert.True(t, wiring[0].NeedResponseBody)
}

// TestBuildWiringUnionMixedModes pins that the body-needs union is taken
// across every covered rule's *effective* policy regardless of mode: an
// Off rule contributes no body needs of its own, but doesn't shrink the
// union either - a sibling Blocking rule's needs still apply to the whole
// route's wiring, since wiring is per-route while engine selection stays
// per-rule (see RouteWiring's doc comment). The accepted cost: the Off
// rule's own traffic still streams bodies through ext_proc even though its
// engine never inspects them, since one route gets exactly one wiring.
func TestBuildWiringUnionMixedModes(t *testing.T) {
	healthOff := newPolicy("health-off", httpRouteTargetRef("shop", new(gatewayv1.SectionName("health"))))
	healthOff.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeOff

	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewayDefault.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	route := wiringTestRoute("shared-gw")
	route.Spec.Rules = []gatewayv1.HTTPRouteRule{
		{Name: new(gatewayv1.SectionName("health"))},
		{},
	}

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{healthOff, gatewayDefault},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, alwaysCompiles)

	wiring := result.Wiring

	require.Len(t, wiring, 1, "one wiring per route, not per rule")
	assert.True(t, wiring[0].NeedRequestBody, "the sibling Blocking rule's needs must not be lost to the Off rule's lack of any")
	assert.True(t, wiring[0].NeedResponseBody)
}
