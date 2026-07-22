package v1alpha1

import (
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// PolicyTargetReference identifies the Gateway API object (Gateway or
// HTTPRoute) that a WAFPolicy/DLPPolicy attaches to.
//
// It mirrors the upstream Gateway API policy-attachment reference form (see
// sigs.k8s.io/gateway-api/apis/v1.NamespacedPolicyTargetReference), extended
// with an optional SectionName so a policy can target a single listener
// (when Kind is Gateway) or a single route rule (when Kind is HTTPRoute).
// Upstream does not currently ship a combined Namespace+SectionName
// reference type, so this struct is hand-written rather than reused
// directly.
type PolicyTargetReference struct {
	// group is the group of the target resource.
	// +kubebuilder:validation:Required
	Group gatewayv1.Group `json:"group"`

	// kind is the kind of the target resource. Only "Gateway" and "HTTPRoute"
	// (group gateway.networking.k8s.io) are supported.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Gateway;HTTPRoute
	Kind gatewayv1.Kind `json:"kind"`

	// name is the name of the target resource.
	// +kubebuilder:validation:Required
	Name gatewayv1.ObjectName `json:"name"`

	// namespace is the namespace of the target resource. WAFPolicy/DLPPolicy
	// objects live in the platform-owned namespace (e.g.
	// gateway-protector-system) while the targeted Gateway/HTTPRoute usually
	// lives elsewhere, so this field is required to let the controller
	// resolve cross-namespace targets unambiguously.
	// +kubebuilder:validation:Required
	Namespace gatewayv1.Namespace `json:"namespace"`

	// sectionName targets a specific listener (when kind is Gateway) or a
	// specific route rule (when kind is HTTPRoute). When unset, the policy
	// applies to the whole Gateway/HTTPRoute.
	// +optional
	SectionName *gatewayv1.SectionName `json:"sectionName,omitempty"`
}

// LocalRuleSetReference references a WAFRuleSet living in the same namespace
// as the WAFPolicy that references it (see WAFPolicySpec.CustomRulesRefs).
type LocalRuleSetReference struct {
	// name is the name of the referenced WAFRuleSet, in the same namespace
	// as the WAFPolicy referencing it.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// Status condition types shared by WAFPolicy/DLPPolicy, following the
// Gateway API status-conditions convention
//   - Accepted: the policy is valid, resolves to an existing target, and
//     does not conflict with another policy of the same kind on the same
//     attachment point (see ConditionReasonConflicted below).
//   - Programmed: the gateway is wired and the engine is live in the data
//     plane.
const (
	// ConditionTypeAccepted mirrors gatewayv1.PolicyConditionAccepted.
	ConditionTypeAccepted = string(gatewayv1.PolicyConditionAccepted)

	// ConditionTypeProgrammed mirrors the "Programmed" condition type used
	// elsewhere in Gateway API (e.g. GatewayConditionProgrammed,
	// ListenerConditionProgrammed).
	ConditionTypeProgrammed = "Programmed"
)

// Condition reasons shared by WAFPolicy/DLPPolicy.
const (
	// ConditionReasonAccepted mirrors gatewayv1.PolicyReasonAccepted; used
	// with ConditionTypeAccepted=True.
	ConditionReasonAccepted = string(gatewayv1.PolicyReasonAccepted)

	// ConditionReasonInvalid mirrors gatewayv1.PolicyReasonInvalid; used with
	// ConditionTypeAccepted=False when the policy is syntactically or
	// semantically invalid.
	ConditionReasonInvalid = string(gatewayv1.PolicyReasonInvalid)

	// ConditionReasonTargetNotFound mirrors gatewayv1.PolicyReasonTargetNotFound;
	// used with ConditionTypeAccepted=False when targetRef does not resolve.
	ConditionReasonTargetNotFound = string(gatewayv1.PolicyReasonTargetNotFound)

	// ConditionReasonConflicted mirrors gatewayv1.PolicyReasonConflicted; used
	// with ConditionTypeAccepted=False when another policy of the same kind
	// already targets the exact same attachment point (e.g. two WAFPolicy
	// objects both targeting the same Gateway, or the same HTTPRoute +
	// optional sectionName). This is distinct from one policy overriding
	// another at a different attachment level (a Gateway-level default
	// overridden by a Route-level policy): that is the intended
	// most-specific-wins behavior, not a conflict. When two policies of the
	// same kind do race for the same attachment point, the older one (by
	// creationTimestamp) wins and the newer one gets this reason; the data
	// plane keeps running whatever engine was already compiled and accepted,
	// rather than an undefined or unprotected state.
	ConditionReasonConflicted = string(gatewayv1.PolicyReasonConflicted)

	// ConditionReasonProgrammed is used with ConditionTypeProgrammed=True once
	// the gateway is wired and the engine is live in the data plane.
	ConditionReasonProgrammed = "Programmed"

	// ConditionReasonPending is used with ConditionTypeProgrammed=False while
	// the controller has not finished wiring the gateway / pushing the engine
	// to the data plane yet.
	ConditionReasonPending = "Pending"

	// ConditionReasonCompileFailed is used with ConditionTypeProgrammed=False
	// when the policy is Accepted but its composed Coraza/SecLang directives
	// (embedded Core Rule Set + paranoiaLevel + anomalyThreshold +
	// exclusions + referenced WAFRuleSet.spec.rules) failed to compile, so
	// the policy could not be included in the processor's data-plane
	// config. The condition message carries the compiler error.
	ConditionReasonCompileFailed = "CompileFailed"
)
