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
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

// alwaysCompiles is a DryCompiler that never fails, for tests that don't
// care about the compile-failure path.
func alwaysCompiles(string, string) error { return nil }

// findBinding returns the binding for the whole kind/namespace/name
// object, or nil.
func findBinding(cfg *procconfig.Config, kind, namespace, name string) *procconfig.Binding {
	for i := range cfg.Bindings {
		b := &cfg.Bindings[i]
		if b.Kind == kind && b.Namespace == namespace && b.Name == name && b.SectionName == "" {
			return b
		}
	}

	return nil
}

func TestBuildPublishesOneBindingPerPolicy(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewayDefault.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	listener := newPolicy("gw-admin", gatewayTargetRef("infra", "shared-gw", new(gatewayv1.SectionName("admin"))))
	listener.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeDetection

	route := newPolicy("route", httpRouteTargetRef("shop", nil))
	route.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking
	route.Spec.ParanoiaLevel = 2

	rule := newPolicy("rule", httpRouteTargetRef("shop", new(gatewayv1.SectionName("health"))))
	rule.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeOff

	result := Build(Input{
		Policies: []*gwpv1alpha1.WAFPolicy{rule, route, listener, gatewayDefault},
	}, alwaysCompiles)

	require.Len(t, result.PolicyResults, 4)
	for _, policyResult := range result.PolicyResults {
		require.NoError(t, policyResult.Err)
	}

	cfg := result.Config
	assert.Equal(t, procconfig.SchemaVersion, cfg.SchemaVersion)

	keys := func(policy *gwpv1alpha1.WAFPolicy) *procconfig.WAFRef {
		return &procconfig.WAFRef{EngineKey: EngineKey(RenderDirectives(policy, nil))}
	}

	assert.Equal(t, []procconfig.Binding{
		{Kind: "Gateway", Namespace: "infra", Name: "shared-gw", WAF: keys(gatewayDefault)},
		{Kind: "Gateway", Namespace: "infra", Name: "shared-gw", SectionName: "admin", WAF: keys(listener)},
		{Kind: "HTTPRoute", Namespace: "team-shop", Name: "shop", WAF: keys(route)},
		{Kind: "HTTPRoute", Namespace: "team-shop", Name: "shop", SectionName: "health", WAF: keys(rule)},
	}, cfg.Bindings, "one binding per policy, in canonical order")

	assert.Len(t, cfg.Directives, 4)
	for _, binding := range cfg.Bindings {
		assert.Contains(t, cfg.Directives, binding.WAF.EngineKey)
	}

	require.NoError(t, procconfig.Validate(cfg))
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
	require.Len(t, result.Config.Bindings, 2)
	assert.Equal(t, result.Config.Bindings[0].WAF, result.Config.Bindings[1].WAF)
}

// TestBuildFailedPolicyClaimsItsAttachmentPoint pins that a policy whose
// directives fail to compile still gets a binding, but without an engine:
// requests that resolve to it continue uninspected, instead of falling
// back to a less specific policy (see procconfig.Snapshot.Resolve).
func TestBuildFailedPolicyClaimsItsAttachmentPoint(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewayDefault.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	broken := newPolicy("broken", httpRouteTargetRef("shop", nil))
	broken.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeDetection

	brokenKey := EngineKey(RenderDirectives(broken, nil))
	failingCompile := func(engineKey, _ string) error {
		if engineKey == brokenKey {
			return errors.New("boom")
		}

		return nil
	}

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{gatewayDefault, broken},
		HTTPRoutes: []*gatewayv1.HTTPRoute{shopRoute([]gatewayv1.ParentReference{infraParentRef("shared-gw", nil)}, gatewayv1.HTTPRouteRule{})},
	}, failingCompile)

	require.Len(t, result.PolicyResults, 2)
	require.NoError(t, result.PolicyResults[0].Err)
	require.Error(t, result.PolicyResults[1].Err)
	assert.Equal(t, 0, result.PolicyResults[0].RouteCount, "the route's own policy hides the gateway default")
	assert.Equal(t, 0, result.PolicyResults[1].RouteCount)

	cfg := result.Config
	assert.NotContains(t, cfg.Directives, brokenKey)

	binding := findBinding(cfg, "HTTPRoute", "team-shop", "shop")
	require.NotNil(t, binding, "a policy that failed to compile must still claim its attachment point")
	assert.Nil(t, binding.WAF)

	assert.Empty(t, result.Wiring, "a route whose only reachable policy failed to compile must not be wired")
	require.NoError(t, procconfig.Validate(cfg))
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
	require.Len(t, result.Config.Bindings, 1)
	assert.Nil(t, result.Config.Bindings[0].WAF)
}

func TestBuildRouteOptOutGetsTheOffEngine(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewayDefault.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeDetection

	routeOptOut := newPolicy("route-off", httpRouteTargetRef("status-page", nil))
	routeOptOut.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeOff

	result := Build(Input{
		Policies: []*gwpv1alpha1.WAFPolicy{gatewayDefault, routeOptOut},
	}, alwaysCompiles)

	require.Len(t, result.PolicyResults, 2)
	require.NoError(t, result.PolicyResults[0].Err)
	require.NoError(t, result.PolicyResults[1].Err)

	cfg := result.Config
	require.Len(t, cfg.Directives, 2, "the Detection default and the Off opt-out are different engines and must both be published")

	routeBinding := findBinding(cfg, "HTTPRoute", "team-shop", "status-page")
	require.NotNil(t, routeBinding)
	require.NotNil(t, routeBinding.WAF)
	assert.Equal(t, offEngineDirectives, cfg.Directives[routeBinding.WAF.EngineKey])

	gatewayBinding := findBinding(cfg, "Gateway", "infra", "shared-gw")
	require.NotNil(t, gatewayBinding)
	require.NotNil(t, gatewayBinding.WAF)
	assert.Contains(t, cfg.Directives[gatewayBinding.WAF.EngineKey], "SecRuleEngine DetectionOnly")
}

// TestBuildRouteModeOverridesGatewayMode pins that a route-level policy's
// engine.mode fully replaces the Gateway-level default's for that route -
// in both directions (stricter-than-default and looser-than-default) -
// since the processor picks exactly one binding per request with no notion
// of "strictest wins" across attachment levels (see
// docs/policy-attachment.md). The Gateway's own engine is still compiled
// and published (it may cover other routes), it just isn't the one a
// request of this route resolves to.
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

			result := Build(Input{
				Policies:   []*gwpv1alpha1.WAFPolicy{gatewayDefault, routeOverride},
				HTTPRoutes: []*gatewayv1.HTTPRoute{shopRoute([]gatewayv1.ParentReference{infraParentRef("shared-gw", nil)}, gatewayv1.HTTPRouteRule{})},
			}, alwaysCompiles)

			require.Len(t, result.PolicyResults, 2)
			require.NoError(t, result.PolicyResults[0].Err)
			require.NoError(t, result.PolicyResults[1].Err)

			cfg := result.Config
			require.Len(t, cfg.Directives, 2, "the gateway default and the route override are different engines and must both be published")

			routeBinding := findBinding(cfg, "HTTPRoute", "team-shop", "shop")
			require.NotNil(t, routeBinding)
			require.NotNil(t, routeBinding.WAF)
			assert.Contains(t, cfg.Directives[routeBinding.WAF.EngineKey], tt.wantRouteDirective,
				"the route's binding must point at the route policy's engine, not the gateway's")

			gatewayBinding := findBinding(cfg, "Gateway", "infra", "shared-gw")
			require.NotNil(t, gatewayBinding)
			require.NotNil(t, gatewayBinding.WAF)
			assert.NotContains(t, cfg.Directives[gatewayBinding.WAF.EngineKey], tt.wantRouteDirective,
				"the gateway's own engine must remain unaffected by the route override")
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
	assert.Len(t, result.Config.Bindings, 1)
}

// TestBuildRouteCountCountsReachableRoutes pins RouteCount's meaning: the
// number of wired HTTPRoutes a policy can apply to. A gateway default is
// not counted for a route whose own policy hides it.
func TestBuildRouteCountCountsReachableRoutes(t *testing.T) {
	gatewayDefault := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	gatewayDefault.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	routeOverride := newPolicy("route-override", httpRouteTargetRef("covered", nil))
	routeOverride.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeDetection

	newRoute := func(name string) *gatewayv1.HTTPRoute {
		route := shopRoute([]gatewayv1.ParentReference{infraParentRef("shared-gw", nil)}, gatewayv1.HTTPRouteRule{})
		route.Name = name

		return route
	}

	result := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{gatewayDefault, routeOverride},
		HTTPRoutes: []*gatewayv1.HTTPRoute{newRoute("a"), newRoute("b"), newRoute("covered")},
	}, alwaysCompiles)

	require.Len(t, result.PolicyResults, 2)
	assert.Equal(t, 2, result.PolicyResults[0].RouteCount)
	assert.Equal(t, 1, result.PolicyResults[1].RouteCount)
	assert.Len(t, result.Wiring, 3)
}

// TestBuildConfigDoesNotDependOnHTTPRoutes pins that HTTPRoutes only
// decide the wiring: the published config, and so its hash, stays the same
// when routes come and go.
func TestBuildConfigDoesNotDependOnHTTPRoutes(t *testing.T) {
	policy := newPolicy("gw-default", gatewayTargetRef("infra", "shared-gw", nil))
	policy.Spec.Engine.Mode = gwpv1alpha1.WAFEngineModeBlocking

	withoutRoutes := Build(Input{Policies: []*gwpv1alpha1.WAFPolicy{policy}}, alwaysCompiles)
	withRoutes := Build(Input{
		Policies:   []*gwpv1alpha1.WAFPolicy{policy},
		HTTPRoutes: []*gatewayv1.HTTPRoute{shopRoute([]gatewayv1.ParentReference{infraParentRef("shared-gw", nil)}, gatewayv1.HTTPRouteRule{})},
	}, alwaysCompiles)

	withoutJSON, err := json.Marshal(withoutRoutes.Config)
	require.NoError(t, err)
	withJSON, err := json.Marshal(withRoutes.Config)
	require.NoError(t, err)

	assert.Equal(t, string(withoutJSON), string(withJSON)) //nolint:testifylint // byte-exact equality: the published config's hash must not change
	assert.Empty(t, withoutRoutes.Wiring)
	assert.Len(t, withRoutes.Wiring, 1)
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
						ParentRefs: []gatewayv1.ParentReference{infraParentRef(gateways[i], nil)},
					},
					Rules: []gatewayv1.HTTPRouteRule{{}},
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

	require.Len(t, forward.Config.Bindings, 3)

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
