package processorconfig

import (
	"fmt"
	"log/slog"
	"sort"

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

	// HTTPRoutes is every HTTPRoute in the cluster, used to decide which
	// routes need wiring (see candidatePolicies). It never changes the
	// published Config.
	HTTPRoutes []*gatewayv1.HTTPRoute
}

// PolicyResult reports the outcome of trying to include one Accepted
// WAFPolicy in the built config: either it compiled successfully (Err is
// nil; RouteCount is how many wired HTTPRoutes it can apply to, possibly
// zero if it currently protects no route) or its composed directives failed
// to compile (Err is non-nil; the policy's binding has no engine, and every
// request that resolves to it continues uninspected).
type PolicyResult struct {
	Policy     *gwpv1alpha1.WAFPolicy
	RouteCount int
	Err        error
}

// BuildResult is everything one Build pass produces.
type BuildResult struct {
	// Config is the processor's data-plane config to publish: one
	// directive block per distinct rendered engine, and one binding per
	// Accepted policy attaching its engine to the policy's target.
	Config *procconfig.Config

	// PolicyResults reports, for every policy in Build's input, whether it
	// was included in Config or excluded because its directives failed to
	// compile (see PolicyResult).
	PolicyResults []PolicyResult

	// Wiring is one entry per HTTPRoute that at least one successfully
	// compiled policy can apply to: the ext_proc attachment that route
	// needs in the gateway (see internal/controller's generation of
	// AgentgatewayPolicy objects from this).
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
// since only compilation success/failure matters here. The compiled engine
// is closed before returning so its entries in Coraza's process-wide
// memoize cache for compiled regex/aho-corasick patterns don't leak (see
// config.Snapshot.Close): the controller may dry-compile many engines over
// its lifetime, one per distinct rendered directive block. A close failure
// only logs - it says nothing about whether directives are valid, so it
// must never cause DryCompile's caller to exclude an otherwise-good policy.
func CorazaDryCompile(engineKey, directives string) error {
	snapshot, err := procconfig.Compile(&procconfig.Config{Directives: map[string]string{engineKey: directives}}, nil)
	if err != nil {
		return fmt.Errorf("engine %q: %w", engineKey, err)
	}

	if closeErr := snapshot.Close(); closeErr != nil {
		slog.Default().Error("Failed to close dry-compiled WAF engine",
			slog.String("engine_key", engineKey), slog.Any("error", closeErr))
	}

	return nil
}

// Build renders a procconfig.Config from input: one directive block per
// distinct rendered engine (deduplicated by EngineKey) and one binding per
// Accepted policy, attaching the policy's engine to its spec.targetRef.
// compile dry-compiles each new engine's directives before it is included
// in the result.
//
// The published Config depends only on policies and rule sets, never on
// HTTPRoutes: the processor selects a binding from the identity that
// agentgateway reports for each request (see procconfig.Snapshot.Resolve),
// so it needs no inventory of hosts and paths. HTTPRoutes only decide the
// wiring (see candidatePolicies).
//
// Build never returns an error itself: a policy whose directives fail to
// compile is reported via its PolicyResult.Err, and its binding is
// published without an engine - so requests that resolve to it continue
// uninspected instead of falling back to a less specific policy - rather
// than failing the whole build (see docs/wafpolicy-lifecycle.md).
//
// Build's Config.Bindings is canonically ordered (sorted by kind, then
// namespace, name, and sectionName) regardless of input.Policies' own
// order: that order follows the controller-runtime cache's List, which is
// documented to be arbitrary (client-go's underlying store is map-backed),
// so two Build calls over identical accepted-policy state could otherwise
// render byte-different (but logically identical) Config values.
// GRPCPublisher.Publish hashes the rendered JSON to decide whether a config
// push is a no-op, so this ordering guarantee is what keeps that hash
// stable across reconciles that didn't actually change anything - without
// it, every reconcile could look like a "new" config and force every
// processor replica to needlessly recompile all its engines.
func Build(input Input, compile DryCompiler) BuildResult {
	ruleSetIndex := indexRuleSets(input.RuleSets)
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

	return BuildResult{
		Config: &procconfig.Config{
			SchemaVersion: procconfig.SchemaVersion,
			Directives:    directives,
			Bindings:      buildBindings(policyIdx, engineKeyByPolicy),
		},
		PolicyResults: results,
		Wiring:        buildWiring(input.HTTPRoutes, policyIdx, engineKeyByPolicy, resultByPolicy),
	}
}

// buildBindings returns one binding per indexed policy, in the canonical
// order Build's doc comment documents as an invariant. A policy without an
// engine key (its directives failed to compile) gets a binding without an
// engine (see procconfig.Binding.WAF).
func buildBindings(policyIdx *policyIndex, engineKeyByPolicy map[*gwpv1alpha1.WAFPolicy]string) []procconfig.Binding {
	bindings := make([]procconfig.Binding, 0, len(policyIdx.byPoint))

	for point, policy := range policyIdx.byPoint {
		binding := procconfig.Binding{
			Kind:        point.Kind,
			Namespace:   point.Namespace,
			Name:        point.Name,
			SectionName: point.SectionName,
		}

		if engineKey, compiled := engineKeyByPolicy[policy]; compiled {
			binding.WAF = &procconfig.WAFRef{EngineKey: engineKey}
		}

		bindings = append(bindings, binding)
	}

	// Attachment points are unique, so (kind, namespace, name,
	// sectionName) is a total order and a plain (non-stable) sort is
	// enough.
	sort.Slice(bindings, func(i, j int) bool {
		a, b := bindings[i], bindings[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}

		return a.SectionName < b.SectionName
	})

	return bindings
}

// buildWiring returns one RouteWiring per HTTPRoute that at least one
// successfully compiled policy can apply to (see candidatePolicies), and
// counts that route in each such policy's RouteCount. A candidate whose
// directives failed to compile neither wires the route nor contributes
// body needs: the processor runs no engine for it.
func buildWiring(
	httpRoutes []*gatewayv1.HTTPRoute,
	policyIdx *policyIndex,
	engineKeyByPolicy map[*gwpv1alpha1.WAFPolicy]string,
	resultByPolicy map[*gwpv1alpha1.WAFPolicy]*PolicyResult,
) []RouteWiring {
	var wiring []RouteWiring

	for _, route := range httpRoutes {
		var routeWiring *RouteWiring

		for policy := range candidatePolicies(policyIdx, route) {
			if _, compiled := engineKeyByPolicy[policy]; !compiled {
				continue
			}

			if routeWiring == nil {
				routeWiring = &RouteWiring{Route: route}
			}

			routeWiring.NeedRequestBody = routeWiring.NeedRequestBody || policyNeedsRequestBody(policy)
			routeWiring.NeedResponseBody = routeWiring.NeedResponseBody || policyNeedsResponseBody(policy)
			resultByPolicy[policy].RouteCount++
		}

		if routeWiring != nil {
			wiring = append(wiring, *routeWiring)
		}
	}

	return wiring
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
