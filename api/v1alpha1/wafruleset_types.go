package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// WAFCustomRule is a single raw Coraza/ModSecurity SecRule directive block,
// identified by its numeric rule id.
type WAFCustomRule struct {
	// id is the numeric SecRule id. It must be in the site-local range
	// 1-99999, which is the SecLang convention reserved for a site's own
	// custom rules (as opposed to 100000-899999, historically assigned to
	// various commercial/community rule vendors; 900000-999999, the OWASP
	// Core Rule Set itself; 9500000-9599999, registered CRS plugins; and
	// 10000000-10000099, reserved by gateway-protector for its own
	// generated directives). It is
	// the author's responsibility to keep ids unique within a WAFRuleSet
	// and across every other WAFRuleSet referenced by the same WAFPolicy.
	//
	// This validates the declared id field only, not any id that might
	// also appear inside the raw directive text below - a mismatch between
	// the two is still only caught at dry-compile time.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self >= 1",message="rule id must be a positive integer"
	// +kubebuilder:validation:XValidation:rule="self <= 99999",message="ids above 99999 are reserved (100000-899999 historical vendor assignments, 900000-999999 OWASP Core Rule Set, 9500000-9599999 CRS plugins, 10000000-10000099 gateway-protector); custom rules must use the site-local range 1-99999"
	ID int64 `json:"id"`

	// directive is one or more raw SecRule lines composing this rule.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
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
