package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// WAFCustomRule is a single raw Coraza/ModSecurity SecRule directive block,
// identified by its numeric rule id.
type WAFCustomRule struct {
	// id is the numeric SecRule id. It is the author's responsibility to keep
	// ids unique within a WAFRuleSet and outside of the ranges reserved by
	// the Core Rule Set and other WAFRuleSet objects referenced by the same
	// WAFPolicy; the admission webhook's dry-compile step (see TODO in
	// internal/webhook/v1alpha1/wafpolicy_webhook.go) additionally enforces
	// whatever uniqueness rules Coraza itself requires.
	// +kubebuilder:validation:Required
	ID int64 `json:"id"`

	// directive is one or more raw SecRule lines composing this rule.
	// +kubebuilder:validation:Required
	Directive string `json:"directive"`
}

// WAFRuleSetSpec defines the desired state of WAFRuleSet.
type WAFRuleSetSpec struct {
	// rules are raw Coraza/ModSecurity SecRule directive blocks, referenced
	// from WAFPolicy.customRulesRefs to avoid pasting raw directives inline
	// in every WAFPolicy.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Rules []WAFCustomRule `json:"rules"`
}

// WAFRuleSetStatus defines the observed state of WAFRuleSet.
type WAFRuleSetStatus struct {
	// conditions represent the current state of the WAFRuleSet resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// WAFRuleSet is the Schema for the wafrulesets API. It is a reusable bundle
// of custom SecRule directives referenced from one or more WAFPolicy objects
// in the same namespace via customRulesRefs.
type WAFRuleSet struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of WAFRuleSet
	// +required
	Spec WAFRuleSetSpec `json:"spec"`

	// status defines the observed state of WAFRuleSet
	// +optional
	Status WAFRuleSetStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// WAFRuleSetList contains a list of WAFRuleSet
type WAFRuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`

	Items []WAFRuleSet `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &WAFRuleSet{}, &WAFRuleSetList{})
		return nil
	})
}
