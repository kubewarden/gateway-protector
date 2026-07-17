package controller

import (
	"fmt"
	"slices"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// Field indexes.
//
// A controller-runtime manager doesn't hit the API server for every List: it
// keeps a local cache (populated by watching each resource type) and List
// normally has to scan every cached object of that kind. A field index
// (mgr.GetFieldIndexer().IndexField) tells that cache to also file each
// object under one or more extra string keys, computed by an indexer
// function, so a later List with client.MatchingFields{key: value} becomes
// an O(1) lookup instead of a full scan - like a database index.
//
// The index name below (e.g. wafpolicyAttachmentIndexKey) is only ever used
// as that map key: it is not a JSON/Go field path and nothing parses it as
// one, even though upstream examples often name an index after a real field
// they happen to index verbatim (e.g. ".spec.nodeName" on Pods). Here all
// three indexes store a *computed* composite key instead (see
// indexWAFPolicyByAttachment/indexWAFPolicyByTarget/
// indexWAFPolicyByCustomRulesRef below), so the names are deliberately
// "wafpolicy.<purpose>" rather than a dotted path, to avoid implying a field
// that doesn't exist.
//
// Because indexes only exist in the cache, client.MatchingFields queries
// only work against a cache-backed client (e.g. mgr.GetClient()) - sending
// one straight to the API server fails with "field label not supported"
// (see the comment on the reconciler construction in
// wafpolicy_controller_test.go for where this bit us during testing).

// wafpolicyAttachmentIndexKey indexes every WAFPolicy by its exact
// attachment point (see attachmentKey), used to find every WAFPolicy
// competing for the same attachment point as a given one (the
// conflict-detection step in Reconcile).
const wafpolicyAttachmentIndexKey = "wafpolicy.attachmentPoint"

// wafpolicyTargetIndexKey indexes every WAFPolicy by the Gateway/HTTPRoute
// it targets, ignoring sectionName (see targetKey), used to re-resolve
// targetRef when that Gateway/HTTPRoute changes (see the Watches calls in
// SetupWithManager).
const wafpolicyTargetIndexKey = "wafpolicy.targetObject"

// wafpolicyCustomRulesRefIndexKey indexes every WAFPolicy by each WAFRuleSet
// it references from spec.customRulesRefs (see indexWAFPolicyByCustomRulesRef),
// used to re-resolve that reference when the WAFRuleSet changes.
const wafpolicyCustomRulesRefIndexKey = "wafpolicy.customRulesRef"

// attachmentKey encodes the exact attachment point a WAFPolicy targets:
// kind + namespace + name + optional sectionName. Two WAFPolicy objects
// sharing an attachmentKey are competing for the same attachment point and
// therefore conflict (see ConditionReasonConflicted): a Gateway-level policy
// being overridden by a Route-level policy targets a *different*
// attachmentKey (different kind/name) and is not a conflict.
func attachmentKey(ref gwpv1alpha1.PolicyTargetReference) string {
	section := ""
	if ref.SectionName != nil {
		section = string(*ref.SectionName)
	}

	return fmt.Sprintf("%s/%s/%s/%s", ref.Kind, ref.Namespace, ref.Name, section)
}

// targetKey encodes the Gateway/HTTPRoute a WAFPolicy targets, ignoring
// sectionName, so every policy pointed at that object - no matter which
// section - is found when the object itself changes.
func targetKey(ref gwpv1alpha1.PolicyTargetReference) string {
	return fmt.Sprintf("%s/%s/%s", ref.Kind, ref.Namespace, ref.Name)
}

// indexWAFPolicyByAttachment is a client.IndexerFunc registered against
// wafpolicyAttachmentIndexKey.
func indexWAFPolicyByAttachment(obj client.Object) []string {
	policy, ok := obj.(*gwpv1alpha1.WAFPolicy)
	if !ok {
		return nil
	}

	return []string{attachmentKey(policy.Spec.TargetRef)}
}

// indexWAFPolicyByTarget is a client.IndexerFunc registered against
// wafpolicyTargetIndexKey.
func indexWAFPolicyByTarget(obj client.Object) []string {
	policy, ok := obj.(*gwpv1alpha1.WAFPolicy)
	if !ok {
		return nil
	}

	return []string{targetKey(policy.Spec.TargetRef)}
}

// indexWAFPolicyByCustomRulesRef is a client.IndexerFunc registered against
// wafpolicyCustomRulesRefIndexKey. It returns one entry per WAFRuleSet
// referenced from spec.customRulesRefs (namespace is always the WAFPolicy's
// own, per LocalRuleSetReference's doc comment), so a WAFRuleSet change
// re-enqueues every WAFPolicy that references it.
func indexWAFPolicyByCustomRulesRef(obj client.Object) []string {
	policy, ok := obj.(*gwpv1alpha1.WAFPolicy)
	if !ok {
		return nil
	}

	keys := make([]string, 0, len(policy.Spec.CustomRulesRefs))
	for _, ref := range policy.Spec.CustomRulesRefs {
		keys = append(keys, fmt.Sprintf("%s/%s", policy.Namespace, ref.Name))
	}

	return keys
}

// conflictWinner returns the WAFPolicy that should be Accepted among a set
// of policies competing for the same attachment point: the oldest by
// creationTimestamp, with namespace/name as a stable, deterministic tiebreak
// for objects created at the exact same instant (e.g. simultaneous GitOps
// apply). policies must be non-empty.
func conflictWinner(policies []gwpv1alpha1.WAFPolicy) *gwpv1alpha1.WAFPolicy {
	winner := slices.MinFunc(policies, compareWAFPolicyPrecedence)

	return &winner
}

// compareWAFPolicyPrecedence orders two WAFPolicy objects competing for the
// same attachment point by acceptance precedence: the older
// creationTimestamp sorts first; when they tie (creationTimestamp only has
// second-level resolution, so simultaneous creates are common), the
// lexicographically smaller namespace/name sorts first instead, so every
// replica of the controller agrees deterministically.
func compareWAFPolicyPrecedence(a, b gwpv1alpha1.WAFPolicy) int {
	if c := a.CreationTimestamp.Time.Compare(b.CreationTimestamp.Time); c != 0 {
		return c
	}

	return strings.Compare(namespacedName(&a), namespacedName(&b))
}

func namespacedName(policy *gwpv1alpha1.WAFPolicy) string {
	return policy.Namespace + "/" + policy.Name
}
