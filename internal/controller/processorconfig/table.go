package processorconfig

import (
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// attachmentPoint mirrors internal/controller's attachment-key concept
// (kind + namespace + name + optional sectionName) as a comparable struct,
// so it can be used directly as a map key without string formatting. It is
// intentionally duplicated here rather than imported: this package must not
// depend on internal/controller, which depends on this package instead.
type attachmentPoint struct {
	kind        string
	namespace   string
	name        string
	sectionName string
}

func newAttachmentPoint(ref gwpv1alpha1.PolicyTargetReference) attachmentPoint {
	section := ""
	if ref.SectionName != nil {
		section = string(*ref.SectionName)
	}

	return attachmentPoint{
		kind:        string(ref.Kind),
		namespace:   string(ref.Namespace),
		name:        string(ref.Name),
		sectionName: section,
	}
}

// policyIndex looks up an Accepted WAFPolicy by its exact attachment point.
// Building it assumes every input policy is already the unique winner for
// its attachment point (i.e. conflict resolution - see
// internal/controller/wafpolicy_conflicts.go - has already happened before
// Build is called; there is at most one Accepted policy per attachment
// point by construction).
type policyIndex struct {
	byPoint map[attachmentPoint]*gwpv1alpha1.WAFPolicy
}

func newPolicyIndex(policies []*gwpv1alpha1.WAFPolicy) *policyIndex {
	idx := &policyIndex{byPoint: make(map[attachmentPoint]*gwpv1alpha1.WAFPolicy, len(policies))}
	for _, policy := range policies {
		idx.byPoint[newAttachmentPoint(policy.Spec.TargetRef)] = policy
	}

	return idx
}

func (idx *policyIndex) lookup(kind, namespace, name, sectionName string) (*gwpv1alpha1.WAFPolicy, bool) {
	policy, found := idx.byPoint[attachmentPoint{kind: kind, namespace: namespace, name: name, sectionName: sectionName}]

	return policy, found
}

// effectivePolicyForRule resolves the WAFPolicy that governs a single
// HTTPRoute rule, applying most-specific-wins across four levels (most to
// least specific). See docs/policy-attachment.md for the user-facing
// description of this precedence, with examples.
//
//  1. an HTTPRoute-level WAFPolicy targeting this exact rule (sectionName
//     == rule.Name, only possible when the rule has a name)
//  2. an HTTPRoute-level WAFPolicy targeting the whole route (no
//     sectionName) - applies to every rule not covered by (1)
//  3. a Gateway-level WAFPolicy scoped to the specific listener this
//     route's parentRef names (sectionName == parentRef.sectionName)
//  4. a Gateway-level WAFPolicy with no sectionName - the default for
//     every route attached to that Gateway
//
// Multiple parentRefs are tried in the order HTTPRoute.spec.parentRefs
// lists them, returning the first one with any Gateway-level match; a route
// attached to two Gateways with conflicting defaults for the same path is
// therefore resolved deterministically but not by "combining" both - a
// documented simplification (see the multi-parent-routes open question in
// the project's design notes) rather than full per-listener fidelity.
//
// Returns nil if no policy at any level covers this rule.
func effectivePolicyForRule(idx *policyIndex, route *gatewayv1.HTTPRoute, rule *gatewayv1.HTTPRouteRule) *gwpv1alpha1.WAFPolicy {
	if rule.Name != nil {
		if policy, found := idx.lookup("HTTPRoute", route.Namespace, route.Name, string(*rule.Name)); found {
			return policy
		}
	}

	if policy, found := idx.lookup("HTTPRoute", route.Namespace, route.Name, ""); found {
		return policy
	}

	for _, parentRef := range route.Spec.ParentRefs {
		if !isGatewayParentRef(parentRef) {
			continue
		}

		gwNamespace := route.Namespace
		if parentRef.Namespace != nil {
			gwNamespace = string(*parentRef.Namespace)
		}

		gwName := string(parentRef.Name)

		if parentRef.SectionName != nil {
			if policy, found := idx.lookup("Gateway", gwNamespace, gwName, string(*parentRef.SectionName)); found {
				return policy
			}
		}

		if policy, found := idx.lookup("Gateway", gwNamespace, gwName, ""); found {
			return policy
		}
	}

	return nil
}

// isGatewayParentRef reports whether ref targets a Gateway - the only
// parentRef kind WAFPolicy attachment resolves against. Group/Kind default
// to the Gateway API core group and "Gateway" respectively when unset, per
// the Gateway API spec.
func isGatewayParentRef(ref gatewayv1.ParentReference) bool {
	group := gatewayv1.GroupName
	if ref.Group != nil {
		group = string(*ref.Group)
	}

	kind := "Gateway"
	if ref.Kind != nil {
		kind = string(*ref.Kind)
	}

	return group == gatewayv1.GroupName && kind == "Gateway"
}

// indexGateways builds a lookup table of every given Gateway by
// namespace+name.
func indexGateways(gateways []*gatewayv1.Gateway) map[types.NamespacedName]*gatewayv1.Gateway {
	idx := make(map[types.NamespacedName]*gatewayv1.Gateway, len(gateways))
	for _, gw := range gateways {
		idx[types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}] = gw
	}

	return idx
}

// routeHosts resolves the set of hostnames a route's rule should be
// registered under in the processor's routing table (see
// docs/policy-attachment.md for the user-facing description):
//
//  1. the route's own spec.hostnames, if any;
//  2. otherwise, the hostname of the specific listener its parentRef names
//     (or "*" if that listener has none);
//  3. otherwise, if the referenced Gateway has exactly one listener, that
//     listener's hostname (or "*" if it has none);
//  4. otherwise (no hostnames declared anywhere, or an ambiguous
//     multi-listener Gateway with no sectionName to disambiguate), the
//     catch-all "*" - the same documented simplification noted on
//     effectivePolicyForRule.
func routeHosts(route *gatewayv1.HTTPRoute, gateways map[types.NamespacedName]*gatewayv1.Gateway) []string {
	if len(route.Spec.Hostnames) > 0 {
		hosts := make([]string, len(route.Spec.Hostnames))
		for i, h := range route.Spec.Hostnames {
			hosts[i] = string(h)
		}

		return hosts
	}

	for _, parentRef := range route.Spec.ParentRefs {
		if host, found := parentRefHost(route, parentRef, gateways); found {
			return []string{host}
		}
	}

	return []string{"*"}
}

// parentRefHost resolves the hostname a single parentRef contributes (see
// routeHosts steps 2-3), or ok=false when parentRef doesn't pin down a
// hostname at all (not a Gateway ref, unknown Gateway, or an ambiguous
// multi-listener Gateway with no sectionName to disambiguate).
func parentRefHost(route *gatewayv1.HTTPRoute, parentRef gatewayv1.ParentReference, gateways map[types.NamespacedName]*gatewayv1.Gateway) (string, bool) {
	if !isGatewayParentRef(parentRef) {
		return "", false
	}

	gwNamespace := route.Namespace
	if parentRef.Namespace != nil {
		gwNamespace = string(*parentRef.Namespace)
	}

	gw, found := gateways[types.NamespacedName{Namespace: gwNamespace, Name: string(parentRef.Name)}]
	if !found {
		return "", false
	}

	if parentRef.SectionName != nil {
		for _, listener := range gw.Spec.Listeners {
			if listener.Name == *parentRef.SectionName {
				return listenerHostOrCatchAll(listener), true
			}
		}

		return "", false
	}

	if len(gw.Spec.Listeners) == 1 {
		return listenerHostOrCatchAll(gw.Spec.Listeners[0]), true
	}

	return "", false
}

func listenerHostOrCatchAll(listener gatewayv1.Listener) string {
	if listener.Hostname != nil {
		return string(*listener.Hostname)
	}

	return "*"
}

// rulePaths returns the pathPrefix values the processor's routing table
// should register for rule (see docs/policy-attachment.md for the
// user-facing description): the Value of each Exact/PathPrefix match
// (defaulting to "/" when a match has no Path at all, matching the Gateway
// API default), or "/" alone when the rule has no matches at all (again the
// Gateway API default: no matches means "match every request"). A
// RegularExpression path match cannot be represented in the processor's
// prefix-based table and is skipped - a documented limitation rather than
// an approximation that might over- or under-protect.
func rulePaths(rule *gatewayv1.HTTPRouteRule) []string {
	if len(rule.Matches) == 0 {
		return []string{"/"}
	}

	var paths []string

	for _, match := range rule.Matches {
		if match.Path == nil {
			paths = append(paths, "/")
			continue
		}

		matchType := gatewayv1.PathMatchPathPrefix
		if match.Path.Type != nil {
			matchType = *match.Path.Type
		}

		if matchType == gatewayv1.PathMatchRegularExpression {
			continue
		}

		value := "/"
		if match.Path.Value != nil {
			value = *match.Path.Value
		}

		paths = append(paths, value)
	}

	return paths
}
