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

// alwaysCompiles is a DryCompiler that never fails, for tests that don't
// care about the compile-failure path.
func alwaysCompiles(string, string) error { return nil }

func TestBuildCoversRouteAndSetsRouteCount(t *testing.T) {
	policy := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	policy.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "shared-gw", Namespace: new(gatewayv1.Namespace("infra"))},
				},
			},
			Hostnames: []gatewayv1.Hostname{"shop.example.com"},
			Rules: []gatewayv1.HTTPRouteRule{
				{Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Value: new("/")}}}},
			},
		},
	}

	cfg, results := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{policy},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, alwaysCompiles)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Err)
	assert.Equal(t, 1, results[0].RouteCount)

	require.Len(t, cfg.Routes, 1)
	assert.Equal(t, "shop.example.com", cfg.Routes[0].Host)
	assert.Equal(t, "/", cfg.Routes[0].PathPrefix)
	require.NotNil(t, cfg.Routes[0].WAF)
	assert.Len(t, cfg.Directives, 1)
	assert.Contains(t, cfg.Directives, cfg.Routes[0].WAF.EngineKey)
}

func TestBuildDeduplicatesIdenticalEngines(t *testing.T) {
	policyA := newPolicy("a", gatewayTargetRef("infra", "gw-a", nil))
	policyB := newPolicy("b", gatewayTargetRef("infra", "gw-b", nil))
	policyA.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking
	policyB.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	cfg, results := Build(Input{
		Policies: []*gwpv1alpha1.WAFPolicy{policyA, policyB},
	}, alwaysCompiles)

	require.Len(t, results, 2)
	require.NoError(t, results[0].Err)
	require.NoError(t, results[1].Err)
	assert.Len(t, cfg.Directives, 1, "byte-identical directives from two policies should share one engine")
}

func TestBuildExcludesPolicyThatFailsToCompile(t *testing.T) {
	policy := newPolicy("broken", gatewayTargetRef("infra", "shared-gw", nil))
	policy.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "shared-gw", Namespace: new(gatewayv1.Namespace("infra"))},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{{}},
		},
	}

	failingCompile := func(string, string) error { return errors.New("boom") }

	cfg, results := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{policy},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, failingCompile)

	require.Len(t, results, 1)
	require.Error(t, results[0].Err)
	assert.Equal(t, 0, results[0].RouteCount)
	assert.Empty(t, cfg.Directives)
	assert.Empty(t, cfg.Routes, "a route covered only by a failing policy gets no entry at all")
}

func TestBuildMissingRuleSetIsReportedAsError(t *testing.T) {
	policy := newPolicy("uses-missing-ruleset", gatewayTargetRef("infra", "shared-gw", nil))
	policy.Spec.CustomRulesRefs = []gwpv1alpha1.LocalRuleSetReference{
		{Name: "does-not-exist"},
	}

	cfg, results := Build(Input{
		Policies: []*gwpv1alpha1.WAFPolicy{policy},
	}, alwaysCompiles)

	require.Len(t, results, 1)
	require.Error(t, results[0].Err)
	assert.Empty(t, cfg.Directives)
}

func TestBuildRouteOptOutStillGetsAnExplicitEntry(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewayDefault.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeDetection

	routeOptOut := newPolicy("route-off", httpRouteTargetRef("team-shop", "status-page", nil))
	routeOptOut.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeOff

	gw := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "status-page", Namespace: "team-shop"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "shared-gw", Namespace: new(gatewayv1.Namespace("infra"))},
				},
			},
			Hostnames: []gatewayv1.Hostname{"status.example.com"},
			Rules:     []gatewayv1.HTTPRouteRule{{}},
		},
	}

	cfg, results := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{gatewayDefault, routeOptOut},
		HTTPRoutes: []*gatewayv1.HTTPRoute{gw},
	}, alwaysCompiles)

	require.Len(t, results, 2)
	require.NoError(t, results[0].Err)
	require.NoError(t, results[1].Err)

	require.Len(t, cfg.Routes, 1)
	assert.Equal(t, "status.example.com", cfg.Routes[0].Host)
	assert.Equal(t, offEngineDirectives, cfg.Directives[cfg.Routes[0].WAF.EngineKey])

	require.Len(t, cfg.Directives, 2, "the Detection default and the Off opt-out are different engines and must both be published")

	for engineKey, directives := range cfg.Directives {
		if engineKey == cfg.Routes[0].WAF.EngineKey {
			continue
		}

		assert.Contains(t, directives, "SecRuleEngine DetectionOnly", "the other engine must be the Gateway's Detection default")
	}
}

func TestBuildAcceptedPolicyWithNoCoverageStillCompiles(t *testing.T) {
	policy := newPolicy("unused", gatewayTargetRef("infra", "unused-gw", nil))
	policy.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	cfg, results := Build(Input{
		Policies: []*gwpv1alpha1.WAFPolicy{policy},
	}, alwaysCompiles)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Err)
	assert.Equal(t, 0, results[0].RouteCount)
	assert.Len(t, cfg.Directives, 1, "the engine should still be compiled and published even with zero routes")
}

func TestCorazaDryCompile(t *testing.T) {
	require.NoError(t, CorazaDryCompile("valid", "SecRuleEngine On\n"))
	assert.Error(t, CorazaDryCompile("invalid", "ThisIsNotADirective\n"))
}
