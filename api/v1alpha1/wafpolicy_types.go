package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// WAFEngineMode controls whether the WAF engine blocks matching requests,
// only logs them, or is disabled entirely.
// +kubebuilder:validation:Enum=Blocking;Detection;Off
type WAFEngineMode string

const (
	// WAFEngineModeBlocking rejects requests that match a rule.
	WAFEngineModeBlocking WAFEngineMode = "Blocking"

	// WAFEngineModeDetection evaluates rules and reports matches but never
	// blocks traffic.
	WAFEngineModeDetection WAFEngineMode = "Detection"

	// WAFEngineModeOff disables the WAF engine for the attachment point,
	// e.g. to let a route opt out of a Gateway-level default.
	WAFEngineModeOff WAFEngineMode = "Off"
)

// FailureMode controls what the data plane does when the ext_proc processor
// is unreachable.
// +kubebuilder:validation:Enum=FailClosed;FailOpen
type FailureMode string

const (
	// FailureModeClosed blocks traffic when the processor is unreachable.
	FailureModeClosed FailureMode = "FailClosed"

	// FailureModeOpen forwards traffic when the processor is unreachable.
	FailureModeOpen FailureMode = "FailOpen"
)

// WAFEngineSpec configures the WAF engine's operating mode and its behavior
// when the data plane cannot be reached.
type WAFEngineSpec struct {
	// mode selects whether the engine blocks, only logs, or is disabled.
	// +kubebuilder:validation:Required
	Mode WAFEngineMode `json:"mode"`

	// failureMode controls what happens to traffic when the ext_proc
	// processor is unreachable. There is intentionally no implicit default;
	// every WAFPolicy must state its failure posture explicitly.
	// +kubebuilder:validation:Required
	FailureMode FailureMode `json:"failureMode"`
}

// WAFAnomalyThreshold sets the CRS anomaly-scoring thresholds above which a
// request (or response) is considered an attack.
type WAFAnomalyThreshold struct {
	// inbound is the anomaly score threshold applied to the request phase.
	// +optional
	Inbound int32 `json:"inbound,omitempty"`

	// outbound is the anomaly score threshold applied to the response phase.
	// +optional
	Outbound int32 `json:"outbound,omitempty"`
}

// WAFBodyInspectionSpec toggles and bounds request/response body inspection.
type WAFBodyInspectionSpec struct {
	// enabled toggles body inspection for this phase.
	// +kubebuilder:validation:Required
	Enabled bool `json:"enabled"`

	// maxSize caps the number of bytes buffered for inspection (e.g. "1Mi").
	// Bodies larger than this are handled per the engine's configured
	// behavior for oversized bodies. Only meaningful when enabled is true.
	// +optional
	MaxSize *resource.Quantity `json:"maxSize,omitempty"`
}

// WAFExclusion excludes specific CRS rules (by numeric id) or rule tags from
// evaluation, e.g. to silence a known false positive.
type WAFExclusion struct {
	// byId excludes specific CRS rule ids.
	// +optional
	ByID []int32 `json:"byId,omitempty"`

	// byTag excludes every CRS rule carrying one of the given tags (e.g.
	// "attack-sqli").
	// +optional
	ByTag []string `json:"byTag,omitempty"`
}

// WAFPolicySpec defines the desired state of WAFPolicy.
//
// A WAFPolicy attaches a Coraza + OWASP Core Rule Set WAF engine to a
// Gateway (as the default for all its routes) or to a single HTTPRoute (as
// an override of the Gateway default for that route only) - resolved
// "most-specific-wins" between exactly those two attachment levels, with no
// merging: a Route-level WAFPolicy fully replaces the Gateway-level one for
// that route, it doesn't add to it. See the field docs below for the
// per-field reference, docs/wafpolicy-lifecycle.md for the validation and
// conflict-resolution rules, and docs/processor.md for how the compiled
// result is ultimately consumed by the data plane.
type WAFPolicySpec struct {
	// targetRef identifies exactly one Gateway (applies to all its routes,
	// the common default case) or one HTTPRoute (overrides the Gateway
	// default for that route only).
	// +kubebuilder:validation:Required
	TargetRef PolicyTargetReference `json:"targetRef"`

	// engine configures the WAF engine's mode and failure posture.
	// +kubebuilder:validation:Required
	Engine WAFEngineSpec `json:"engine"`

	// paranoiaLevel selects the CRS paranoia level (1-4); higher levels
	// enable more (and more false-positive-prone) rules. Absent means the
	// Core Rule Set's own default (paranoia level 1).
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4
	ParanoiaLevel int32 `json:"paranoiaLevel,omitempty"`

	// anomalyThreshold sets the inbound/outbound anomaly score thresholds.
	// Absent means the Core Rule Set's own defaults.
	// +optional
	AnomalyThreshold *WAFAnomalyThreshold `json:"anomalyThreshold,omitempty"`

	// requestBody configures request body inspection.
	// +optional
	RequestBody *WAFBodyInspectionSpec `json:"requestBody,omitempty"`

	// responseBody configures response body inspection.
	// +optional
	ResponseBody *WAFBodyInspectionSpec `json:"responseBody,omitempty"`

	// exclusions silence specific CRS rules (by id or tag), e.g. to resolve a
	// known false positive without lowering the paranoia level.
	// +optional
	Exclusions []WAFExclusion `json:"exclusions,omitempty"`

	// customRulesRefs references WAFRuleSet objects, in the same namespace as
	// this WAFPolicy, whose custom SecRule directives are compiled into the
	// engine alongside the Core Rule Set. Referenced WAFRuleSets are
	// rendered in namespace/name order, not the order listed here (this is
	// a listType=map, so list order isn't meaningful and isn't preserved
	// across a server-side-apply merge); SecLang rules that depend on a
	// specific relative order must be placed together within a single
	// WAFRuleSet, whose own spec.rules order is preserved.
	// +optional
	// +listType=map
	// +listMapKey=name
	CustomRulesRefs []LocalRuleSetReference `json:"customRulesRefs,omitempty"`
}

// WAFPolicyStatus defines the observed state of WAFPolicy.
type WAFPolicyStatus struct {
	// conditions represent the current state of the WAFPolicy resource, using
	// the Gateway API status-conditions convention: Accepted (valid, target
	// resolves, not conflicted - see ConditionReasonConflicted) and
	// Programmed (gateway wired, engine live in the data plane).
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"
// +kubebuilder:printcolumn:name="Target Kind",type="string",JSONPath=".spec.targetRef.kind"
// +kubebuilder:printcolumn:name="Target Name",type="string",JSONPath=".spec.targetRef.name"
// +kubebuilder:printcolumn:name="Mode",type="string",JSONPath=".spec.engine.mode"
// +kubebuilder:printcolumn:name="Accepted",type="string",JSONPath=".status.conditions[?(@.type=='Accepted')].status"
// +kubebuilder:printcolumn:name="Programmed",type="string",JSONPath=".status.conditions[?(@.type=='Programmed')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// WAFPolicy is the Schema for the wafpolicies API. It attaches a Coraza +
// OWASP Core Rule Set WAF engine to a Gateway (as the default for all its
// routes) or to a single HTTPRoute (as an override of the Gateway default).
type WAFPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of WAFPolicy
	// +required
	Spec WAFPolicySpec `json:"spec"`

	// status defines the observed state of WAFPolicy
	// +optional
	Status WAFPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// WAFPolicyList contains a list of WAFPolicy
type WAFPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`

	Items []WAFPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &WAFPolicy{}, &WAFPolicyList{})
		return nil
	})
}
