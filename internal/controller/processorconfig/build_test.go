package processorconfig

import (
	"encoding/json"
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

// TestBuildConfigIsDeterministic asserts Build's documented invariant that
// its Config output only depends on the *logical* input, not the order
// input.Policies/input.HTTPRoutes happen to be in - which, in production,
// follows the controller-runtime cache's List and is explicitly
// undocumented/arbitrary (see Build's own doc comment). GRPCPublisher hashes
// the JSON encoding of this Config to detect no-op pushes, so if this test
// ever fails, that hash would flap on every reconcile even when nothing
// meaningful changed, forcing every processor replica to needlessly
// recompile all its engines.
func TestBuildConfigIsDeterministic(t *testing.T) {
	newScenario := func(order []int) Input {
		gateways := []string{"gw-a", "gw-b", "gw-c"}
		modes := []gwpv1alpha1.WAFEngineMode{
			gwpv1alpha1.WAFEngineModeBlocking,
			gwpv1alpha1.WAFEngineModeDetection,
			gwpv1alpha1.WAFEngineModeOff,
		}
		hosts := []string{"a.example.com", "b.example.com", "c.example.com"}

		policies := make([]*gwpv1alpha1.WAFPolicy, 3)
		routes := make([]*gatewayv1.HTTPRoute, 3)

		for _, i := range order {
			policy := newPolicy(gateways[i], gatewayTargetRef("infra", gateways[i], nil))
			policy.Spec.Engine.Mode = modes[i]
			policies[i] = policy

			routes[i] = &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: gateways[i] + "-route", Namespace: "team-shop"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: gatewayv1.ObjectName(gateways[i]), Namespace: new(gatewayv1.Namespace("infra"))},
						},
					},
					Hostnames: []gatewayv1.Hostname{gatewayv1.Hostname(hosts[i])},
					Rules: []gatewayv1.HTTPRouteRule{
						{Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Value: new("/")}}}},
					},
				},
			}
		}

		// Reorder the built slices themselves (not just the construction
		// loop above) so both Policies and HTTPRoutes are actually handed
		// to Build in `order`, mirroring an arbitrarily-ordered cache List.
		orderedPolicies := make([]*gwpv1alpha1.WAFPolicy, 3)
		orderedRoutes := make([]*gatewayv1.HTTPRoute, 3)
		for pos, i := range order {
			orderedPolicies[pos] = policies[i]
			orderedRoutes[pos] = routes[i]
		}

		return Input{Policies: orderedPolicies, HTTPRoutes: orderedRoutes}
	}

	forward := Build(newScenario([]int{0, 1, 2}), alwaysCompiles)
	reversed := Build(newScenario([]int{2, 1, 0}), alwaysCompiles)
	shuffled := Build(newScenario([]int{1, 2, 0}), alwaysCompiles)

	require.Len(t, forward.Config.Routes, 3)

	forwardJSON, err := json.Marshal(forward.Config)
	require.NoError(t, err)
	reversedJSON, err := json.Marshal(reversed.Config)
	require.NoError(t, err)
	shuffledJSON, err := json.Marshal(shuffled.Config)
	require.NoError(t, err)

	// Byte-exact comparison is intentional here, not just JSON-semantic
	// equality (which is all assert.JSONEq would check): what actually
	// needs to be stable is the sha256 hash GRPCPublisher computes over
	// these exact bytes (see its doc comment), so this test's whole point
	// would be undermined by an equality check that tolerates the kind of
	// difference (e.g. array order) that would also change that hash.
	assert.Equal(t, string(forwardJSON), string(reversedJSON), //nolint:testifylint // see comment above: byte-exact equality is the point of this test
		"Build's Config must serialize identically regardless of input order")
	assert.Equal(t, string(forwardJSON), string(shuffledJSON), //nolint:testifylint // see comment above: byte-exact equality is the point of this test
		"Build's Config must serialize identically regardless of input order")
}
