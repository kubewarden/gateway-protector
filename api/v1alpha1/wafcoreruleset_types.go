package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// WAFCoreRuleSetSpec registers an OWASP Core Rule Set bundle baked into the
// processor image, so it can be referenced from a WAFPolicy's
// coreRuleSet.version.
//
// WAFCoreRuleSet is cluster-scoped: it describes what the processor image
// ships, not a per-namespace preference.
type WAFCoreRuleSetSpec struct {
	// version is the CRS version this bundle provides (e.g. "4.14").
	// WAFPolicy.coreRuleSet.version must match a registered WAFCoreRuleSet
	// version.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[0-9]+\.[0-9]+(\.[0-9]+)?$`
	Version string `json:"version"`

	// default marks this bundle as the one used when a WAFPolicy does not
	// pin coreRuleSet.version explicitly. At most one WAFCoreRuleSet should
	// set this to true.
	// +optional
	Default bool `json:"default,omitempty"`

	// image documents which processor image (or digest) ships this bundle.
	// Informational only; the controller does not reconcile against it.
	// +optional
	Image string `json:"image,omitempty"`
}

// WAFCoreRuleSetStatus defines the observed state of WAFCoreRuleSet.
type WAFCoreRuleSetStatus struct {
	// conditions represent the current state of the WAFCoreRuleSet resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"
// +kubebuilder:printcolumn:name="Version",type="string",JSONPath=".spec.version"
// +kubebuilder:printcolumn:name="Default",type="boolean",JSONPath=".spec.default"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// WAFCoreRuleSet is the Schema for the wafcorerulesets API. It registers a
// Core Rule Set bundle that ships with the processor image and that
// WAFPolicy.coreRuleSet.version can reference.
type WAFCoreRuleSet struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of WAFCoreRuleSet
	// +required
	Spec WAFCoreRuleSetSpec `json:"spec"`

	// status defines the observed state of WAFCoreRuleSet
	// +optional
	Status WAFCoreRuleSetStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// WAFCoreRuleSetList contains a list of WAFCoreRuleSet
type WAFCoreRuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`

	Items []WAFCoreRuleSet `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &WAFCoreRuleSet{}, &WAFCoreRuleSetList{})
		return nil
	})
}
