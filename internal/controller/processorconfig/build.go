package processorconfig

import (
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

// Input is everything Build needs to render the processor's data-plane
// configuration.
type Input struct {
	// Policies must contain only WAFPolicy objects with Accepted=True (the
	// caller - see internal/controller/processor_config_reconciler.go - is
	// responsible for filtering) with at most one policy per attachment
	// point (conflict resolution has already happened by the time a policy
	// is Accepted).
	Policies []*gwpv1alpha1.WAFPolicy

	// RuleSets is every WAFRuleSet in the cluster, looked up by
	// namespace+name when resolving a policy's spec.customRulesRefs.
	RuleSets []*gwpv1alpha1.WAFRuleSet

	// Gateways and HTTPRoutes are every such object in the cluster, used to
	// resolve which routes a Gateway-level policy covers and to fall back
	// to a listener's hostname when a route declares none (see routeHosts).
	Gateways   []*gatewayv1.Gateway
	HTTPRoutes []*gatewayv1.HTTPRoute
}

// PolicyResult reports the outcome of trying to include one Accepted
// WAFPolicy in the built config: either it compiled successfully (Err is
// nil; RouteCount is how many host+path entries in the result reference its
// engine, possibly zero if it currently protects no route) or its composed
// directives failed to compile (Err is non-nil; the policy - and everything
// it would have covered - is excluded from the result).
type PolicyResult struct {
	Policy     *gwpv1alpha1.WAFPolicy
	RouteCount int
	Err        error
}

// BuildResult is everything one Build pass produces.
type BuildResult struct {
	// Config is the processor's data-plane config to publish: one
	// directive block per distinct rendered engine, and the host+path
	// routing table selecting one per HTTPRoute rule.
	Config *procconfig.Config

	// PolicyResults reports, for every policy in Build's input, whether it
	// was included in Config or excluded because its directives failed to
	// compile (see PolicyResult).
	PolicyResults []PolicyResult

	// Wiring is one entry per HTTPRoute with at least one successfully
	// covered rule: the ext_proc attachment that route needs in the
	// gateway (see internal/controller's generation of AgentgatewayPolicy
	// objects from this).
	Wiring []RouteWiring
}

// DryCompiler verifies that a single engine's directives compile, without
// requiring the full procconfig.Config/Validate machinery. Build calls it
// once per distinct rendered engine (see EngineKey), so one policy's
// invalid directives can never affect any other's inclusion in the result.
// See CorazaDryCompile for the production implementation.
type DryCompiler func(engineKey, directives string) error

// CorazaDryCompile is the DryCompiler used in production: it compiles
// directives in isolation via internal/processor/config.Compile - the same
// code path the processor itself uses - discarding the resulting engine,
// since only compilation success/failure matters here.
func CorazaDryCompile(engineKey, directives string) error {
	_, err := procconfig.Compile(&procconfig.Config{Directives: map[string]string{engineKey: directives}}, nil)
	if err != nil {
		return fmt.Errorf("engine %q: %w", engineKey, err)
	}

	return nil
}

// Build renders a procconfig.Config from input: one directive block per
// distinct rendered engine (deduplicated by EngineKey) and the host+path
// routing table selecting one per HTTPRoute rule (see
// effectivePolicyForRule and routeHosts/rulePaths). compile dry-compiles
// each new engine's directives before it is included in the result.
//
// Build never returns an error itself: a policy whose directives fail to
// compile is reported via its PolicyResult.Err and simply excluded from the
// returned Config - and from covering any route or producing any wiring -
// rather than failing the whole build (see docs/wafpolicy-lifecycle.md).
func Build(input Input, compile DryCompiler) BuildResult {
	ruleSetIndex := indexRuleSets(input.RuleSets)
	gatewayIndex := indexGateways(input.Gateways)
	policyIdx := newPolicyIndex(input.Policies)

	directives := make(map[string]string)
	engineKeyByPolicy := make(map[*gwpv1alpha1.WAFPolicy]string, len(input.Policies))
	resultByPolicy := make(map[*gwpv1alpha1.WAFPolicy]*PolicyResult, len(input.Policies))
	results := make([]PolicyResult, len(input.Policies))

	for i, policy := range input.Policies {
		results[i] = PolicyResult{Policy: policy}
		resultByPolicy[policy] = &results[i]

		ruleSets, err := resolveRuleSets(policy, ruleSetIndex)
		if err != nil {
			results[i].Err = err
			continue
		}

		rendered := RenderDirectives(policy, ruleSets)
		engineKey := EngineKey(rendered)

		if _, found := directives[engineKey]; !found {
			if err := compile(engineKey, rendered); err != nil {
				results[i].Err = fmt.Errorf("failed to compile directives: %w", err)
				continue
			}

			directives[engineKey] = rendered
		}

		engineKeyByPolicy[policy] = engineKey
	}

	routes, wiring := buildRoutes(input.HTTPRoutes, policyIdx, gatewayIndex, engineKeyByPolicy, resultByPolicy)

	return BuildResult{
		Config:        &procconfig.Config{Directives: directives, Routes: routes},
		PolicyResults: results,
		Wiring:        wiring,
	}
}

func buildRoutes(
	httpRoutes []*gatewayv1.HTTPRoute,
	policyIdx *policyIndex,
	gatewayIndex map[types.NamespacedName]*gatewayv1.Gateway,
	engineKeyByPolicy map[*gwpv1alpha1.WAFPolicy]string,
	resultByPolicy map[*gwpv1alpha1.WAFPolicy]*PolicyResult,
) ([]procconfig.Route, []RouteWiring) {
	var routes []procconfig.Route

	var wiring []RouteWiring

	for _, route := range httpRoutes {
		entries, routeWiring := buildRouteEntries(route, policyIdx, gatewayIndex, engineKeyByPolicy, resultByPolicy)
		if routeWiring == nil {
			continue
		}

		routes = append(routes, entries...)
		wiring = append(wiring, *routeWiring)
	}

	return routes, wiring
}

// buildRouteEntries computes one HTTPRoute's contribution to the routing
// table and its wiring needs. It returns a nil RouteWiring when no rule of
// the route is (successfully) covered by any policy - covered is otherwise
// equivalent to "the route needs wiring" so no separate bool is needed.
// Note entries can be empty even for a covered route (e.g. a rule whose
// only path matches are RegularExpression, which the prefix-based table
// cannot represent), so entries' emptiness cannot be used as that signal.
func buildRouteEntries(
	route *gatewayv1.HTTPRoute,
	policyIdx *policyIndex,
	gatewayIndex map[types.NamespacedName]*gatewayv1.Gateway,
	engineKeyByPolicy map[*gwpv1alpha1.WAFPolicy]string,
	resultByPolicy map[*gwpv1alpha1.WAFPolicy]*PolicyResult,
) ([]procconfig.Route, *RouteWiring) {
	var entries []procconfig.Route

	var wiring *RouteWiring

	for r := range route.Spec.Rules {
		rule := &route.Spec.Rules[r]

		policy := effectivePolicyForRule(policyIdx, route, rule)
		if policy == nil {
			continue
		}

		engineKey, ok := engineKeyByPolicy[policy]
		if !ok {
			// The policy that would cover this rule failed to compile;
			// leave the rule with no entry (unprotected) rather than
			// silently falling back to a different policy.
			continue
		}

		if wiring == nil {
			wiring = &RouteWiring{Route: route}
		}

		wiring.NeedRequestBody = wiring.NeedRequestBody || policyNeedsRequestBody(policy)
		wiring.NeedResponseBody = wiring.NeedResponseBody || policyNeedsResponseBody(policy)

		hosts := routeHosts(route, gatewayIndex)
		paths := rulePaths(rule)
		result := resultByPolicy[policy]

		for _, host := range hosts {
			for _, path := range paths {
				entries = append(entries, procconfig.Route{
					Host:       host,
					PathPrefix: path,
					WAF:        &procconfig.WAFRef{EngineKey: engineKey},
				})
				result.RouteCount++
			}
		}
	}

	return entries, wiring
}

func indexRuleSets(ruleSets []*gwpv1alpha1.WAFRuleSet) map[types.NamespacedName]*gwpv1alpha1.WAFRuleSet {
	idx := make(map[types.NamespacedName]*gwpv1alpha1.WAFRuleSet, len(ruleSets))
	for _, rs := range ruleSets {
		idx[types.NamespacedName{Namespace: rs.Namespace, Name: rs.Name}] = rs
	}

	return idx
}

// resolveRuleSets resolves policy's spec.customRulesRefs (always in the
// policy's own namespace, per LocalRuleSetReference's doc comment) against
// ruleSetIndex. The returned slice is in ref order for error-reporting
// purposes only - RenderDirectives (see writeCustomRules) re-sorts it into a
// canonical namespace/name order before rendering, since customRulesRefs'
// list order isn't semantically meaningful (see that doc comment) and
// mustn't affect the rendered directives or engine key. A missing
// WAFRuleSet is treated as an error here even though the reconciler should
// already have validated this before accepting the policy (see
// internal/controller/wafpolicy_target.go's resolveCustomRulesRefs): this
// is a defensive guard against a WAFRuleSet being deleted in the narrow
// window between that check and this build running, not the primary
// enforcement point.
func resolveRuleSets(policy *gwpv1alpha1.WAFPolicy, ruleSetIndex map[types.NamespacedName]*gwpv1alpha1.WAFRuleSet) ([]*gwpv1alpha1.WAFRuleSet, error) {
	ruleSets := make([]*gwpv1alpha1.WAFRuleSet, 0, len(policy.Spec.CustomRulesRefs))

	for _, ref := range policy.Spec.CustomRulesRefs {
		key := types.NamespacedName{Namespace: policy.Namespace, Name: ref.Name}

		ruleSet, ok := ruleSetIndex[key]
		if !ok {
			return nil, fmt.Errorf("referenced WAFRuleSet %s not found", key)
		}

		ruleSets = append(ruleSets, ruleSet)
	}

	return ruleSets, nil
}
