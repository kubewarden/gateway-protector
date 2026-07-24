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

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{policy},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, alwaysCompiles)

	require.Len(t, result.PolicyResults, 1)
	require.NoError(t, result.PolicyResults[0].Err)
	assert.Equal(t, 1, result.PolicyResults[0].RouteCount)

	cfg := result.Config
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

	result := Build(Input{
		Policies: []*gwpv1alpha1.WAFPolicy{policyA, policyB},
	}, alwaysCompiles)

	require.Len(t, result.PolicyResults, 2)
	require.NoError(t, result.PolicyResults[0].Err)
	require.NoError(t, result.PolicyResults[1].Err)
	assert.Len(t, result.Config.Directives, 1, "byte-identical directives from two policies should share one engine")
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

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{policy},
		HTTPRoutes: []*gatewayv1.HTTPRoute{route},
	}, failingCompile)

	require.Len(t, result.PolicyResults, 1)
	require.Error(t, result.PolicyResults[0].Err)
	assert.Equal(t, 0, result.PolicyResults[0].RouteCount)
	assert.Empty(t, result.Config.Directives)
	assert.Empty(t, result.Config.Routes, "a route covered only by a failing policy gets no entry at all")
}

func TestBuildMissingRuleSetIsReportedAsError(t *testing.T) {
	policy := newPolicy("uses-missing-ruleset", gatewayTargetRef("infra", "shared-gw", nil))
	policy.Spec.CustomRulesRefs = []gwpv1alpha1.LocalRuleSetReference{
		{Name: "does-not-exist"},
	}

	result := Build(Input{
		Policies: []*gwpv1alpha1.WAFPolicy{policy},
	}, alwaysCompiles)

	require.Len(t, result.PolicyResults, 1)
	require.Error(t, result.PolicyResults[0].Err)
	assert.Empty(t, result.Config.Directives)
}

func TestBuildRouteOptOutStillGetsAnExplicitEntry(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewayDefault.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeDetection

	routeOptOut := newPolicy("route-off", httpRouteTargetRef("status-page", nil))
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

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{gatewayDefault, routeOptOut},
		HTTPRoutes: []*gatewayv1.HTTPRoute{gw},
	}, alwaysCompiles)

	require.Len(t, result.PolicyResults, 2)
	require.NoError(t, result.PolicyResults[0].Err)
	require.NoError(t, result.PolicyResults[1].Err)

	cfg := result.Config
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

// TestBuildRouteModeOverridesGatewayMode pins that a route-level policy's
// engine.mode fully replaces the Gateway-level default's for that route -
// in both directions (stricter-than-default and looser-than-default) -
// since effectivePolicyForRule picks exactly one policy per rule with no
// notion of "strictest wins" across attachment levels (see
// docs/policy-attachment.md). The Gateway's own engine is still compiled
// and published (it may cover other routes), it just isn't the one this
// route's table entry points at.
func TestBuildRouteModeOverridesGatewayMode(t *testing.T) {
	tests := []struct {
		name               string
		gatewayMode        gwpv1alpha1.WAFEngineMode
		routeMode          gwpv1alpha1.WAFEngineMode
		wantRouteDirective string
	}{
		{
			name:               "route loosens a Blocking gateway default to Detection",
			gatewayMode:        gwpv1alpha1.WAFEngineModeBlocking,
			routeMode:          gwpv1alpha1.WAFEngineModeDetection,
			wantRouteDirective: "SecRuleEngine DetectionOnly",
		},
		{
			name:               "route tightens a Detection gateway default to Blocking",
			gatewayMode:        gwpv1alpha1.WAFEngineModeDetection,
			routeMode:          gwpv1alpha1.WAFEngineModeBlocking,
			wantRouteDirective: "SecRuleEngine On",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
			gatewayDefault.Spec.Engine.Mode = tt.gatewayMode

			routeOverride := newPolicy("route-override", httpRouteTargetRef("shop", nil))
			routeOverride.Spec.Engine.Mode = tt.routeMode

			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "team-shop"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "shared-gw", Namespace: new(gatewayv1.Namespace("infra"))},
						},
					},
					Hostnames: []gatewayv1.Hostname{"shop.example.com"},
					Rules:     []gatewayv1.HTTPRouteRule{{}},
				},
			}

			result := Build(Input{
				Policies:   []*gwpv1alpha1.WAFPolicy{gatewayDefault, routeOverride},
				HTTPRoutes: []*gatewayv1.HTTPRoute{route},
			}, alwaysCompiles)

			require.Len(t, result.PolicyResults, 2)
			require.NoError(t, result.PolicyResults[0].Err)
			require.NoError(t, result.PolicyResults[1].Err)

			cfg := result.Config
			require.Len(t, cfg.Routes, 1)
			require.NotNil(t, cfg.Routes[0].WAF)
			require.Len(t, cfg.Directives, 2, "the gateway default and the route override are different engines and must both be published")

			routeEngineKey := cfg.Routes[0].WAF.EngineKey
			assert.Contains(t, cfg.Directives[routeEngineKey], tt.wantRouteDirective,
				"the route's table entry must point at the route policy's engine, not the gateway's")

			for engineKey, directives := range cfg.Directives {
				if engineKey == routeEngineKey {
					continue
				}

				assert.NotContains(t, directives, tt.wantRouteDirective,
					"the gateway's own engine must remain unaffected by the route override")
			}
		})
	}
}

func TestBuildAcceptedPolicyWithNoCoverageStillCompiles(t *testing.T) {
	policy := newPolicy("unused", gatewayTargetRef("infra", "unused-gw", nil))
	policy.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	result := Build(Input{
		Policies: []*gwpv1alpha1.WAFPolicy{policy},
	}, alwaysCompiles)

	require.Len(t, result.PolicyResults, 1)
	require.NoError(t, result.PolicyResults[0].Err)
	assert.Equal(t, 0, result.PolicyResults[0].RouteCount)
	assert.Len(t, result.Config.Directives, 1, "the engine should still be compiled and published even with zero routes")
}

func TestCorazaDryCompile(t *testing.T) {
	require.NoError(t, CorazaDryCompile("valid", "SecRuleEngine On\n"))
	assert.Error(t, CorazaDryCompile("invalid", "ThisIsNotADirective\n"))
}
