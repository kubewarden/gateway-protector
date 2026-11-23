package processorconfig

import (
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

// newAttachmentPoint returns the attachment point that ref names. The
// controller's conflict index (attachmentKey in internal/controller)
// encodes the same four values as a string, because a field index needs a
// string key.
func newAttachmentPoint(ref gwpv1alpha1.PolicyTargetReference) procconfig.AttachmentPoint {
	section := ""
	if ref.SectionName != nil {
		section = string(*ref.SectionName)
	}

	return procconfig.AttachmentPoint{
		Kind:        string(ref.Kind),
		Namespace:   string(ref.Namespace),
		Name:        string(ref.Name),
		SectionName: section,
	}
}

// policyIndex looks up an Accepted WAFPolicy by its exact attachment point.
// Building it assumes every input policy is already the unique winner for
// its attachment point (i.e. conflict resolution - see
// internal/controller/wafpolicy_conflicts.go - has already happened before
// Build is called; there is at most one Accepted policy per attachment
// point by construction).
type policyIndex struct {
	byPoint map[procconfig.AttachmentPoint]*gwpv1alpha1.WAFPolicy

	// listenerPolicies holds, for each Gateway, the policies that target
	// one of its listeners.
	listenerPolicies map[types.NamespacedName][]*gwpv1alpha1.WAFPolicy
}

func newPolicyIndex(policies []*gwpv1alpha1.WAFPolicy) *policyIndex {
	idx := &policyIndex{
		byPoint:          make(map[procconfig.AttachmentPoint]*gwpv1alpha1.WAFPolicy, len(policies)),
		listenerPolicies: make(map[types.NamespacedName][]*gwpv1alpha1.WAFPolicy),
	}

	for _, policy := range policies {
		idx.byPoint[newAttachmentPoint(policy.Spec.TargetRef)] = policy
	}

	for point, policy := range idx.byPoint {
		if point.Kind != procconfig.KindGateway || point.SectionName == "" {
			continue
		}

		gateway := types.NamespacedName{Namespace: point.Namespace, Name: point.Name}
		idx.listenerPolicies[gateway] = append(idx.listenerPolicies[gateway], policy)
	}

	return idx
}

func (idx *policyIndex) lookup(kind, namespace, name, sectionName string) (*gwpv1alpha1.WAFPolicy, bool) {
	policy, found := idx.byPoint[procconfig.AttachmentPoint{Kind: kind, Namespace: namespace, Name: name, SectionName: sectionName}]

	return policy, found
}

// candidatePolicies returns the set of every policy that the processor can
// select for some request that agentgateway sends to one of route's rules. The processor tries four levels per request, most
// specific first (see procconfig.Snapshot.Resolve and
// docs/policy-attachment.md):
//
//  1. an HTTPRoute-level WAFPolicy targeting the selected rule (sectionName
//     == rule.Name, only possible when the rule has a name)
//  2. an HTTPRoute-level WAFPolicy targeting the whole route
//  3. a Gateway-level WAFPolicy targeting the listener that accepted the
//     request
//  4. a Gateway-level WAFPolicy targeting the whole Gateway
//
// Levels 3-4 are only reachable when the route has no whole-route policy
// and at least one rule has no rule policy of its own. A request can then
// arrive through any Gateway in spec.parentRefs: through the listener that
// a parentRef names in sectionName, or through any listener of the Gateway
// when the parentRef names none. So every one of these Gateway-level
// policies is a candidate - not only the first parentRef's - since the
// processor selects by the Gateway and listener of each request.
//
// The set has no order. Returns an empty set if no policy can apply to any
// request of route.
func candidatePolicies(idx *policyIndex, route *gatewayv1.HTTPRoute) sets.Set[*gwpv1alpha1.WAFPolicy] {
	candidates := sets.New[*gwpv1alpha1.WAFPolicy]()

	fallsThrough := false

	for i := range route.Spec.Rules {
		rule := &route.Spec.Rules[i]
		if rule.Name != nil {
			if policy, found := idx.lookup(procconfig.KindHTTPRoute, route.Namespace, route.Name, string(*rule.Name)); found {
				candidates.Insert(policy)
				continue
			}
		}

		fallsThrough = true
	}

	if !fallsThrough {
		return candidates
	}

	if policy, found := idx.lookup(procconfig.KindHTTPRoute, route.Namespace, route.Name, ""); found {
		return candidates.Insert(policy)
	}

	for _, parentRef := range route.Spec.ParentRefs {
		addGatewayPolicies(candidates, idx, route.Namespace, parentRef)
	}

	return candidates
}

// addGatewayPolicies adds to candidates the Gateway-level policies that a
// request can resolve to when it arrives through parentRef (see
// candidatePolicies).
func addGatewayPolicies(candidates sets.Set[*gwpv1alpha1.WAFPolicy], idx *policyIndex, routeNamespace string, parentRef gatewayv1.ParentReference) {
	if !isGatewayParentRef(parentRef) {
		return
	}

	gwNamespace := routeNamespace
	if parentRef.Namespace != nil {
		gwNamespace = string(*parentRef.Namespace)
	}

	gwName := string(parentRef.Name)

	if parentRef.SectionName != nil {
		if policy, found := idx.lookup(procconfig.KindGateway, gwNamespace, gwName, string(*parentRef.SectionName)); found {
			candidates.Insert(policy)
			return
		}
	} else {
		candidates.Insert(idx.listenerPolicies[types.NamespacedName{Namespace: gwNamespace, Name: gwName}]...)
	}

	if policy, found := idx.lookup(procconfig.KindGateway, gwNamespace, gwName, ""); found {
		candidates.Insert(policy)
	}
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

	kind := procconfig.KindGateway
	if ref.Kind != nil {
		kind = string(*ref.Kind)
	}

	return group == gatewayv1.GroupName && kind == procconfig.KindGateway
}
