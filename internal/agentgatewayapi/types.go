// Package agentgatewayapi holds a minimal, vendored copy of the
// agentgateway.dev/v1alpha1 AgentgatewayPolicy API types - just the subset
// this controller needs to generate ext_proc wiring policies (see
// internal/controller/processor_config_wiring.go and
// docs/wafpolicy-lifecycle.md's "Gateway wiring").
//
// Vendored from github.com/agentgateway/agentgateway
// (controller/api/v1alpha1/agentgateway) at release v1.7.0 rather than
// imported: the types live in agentgateway's main Go module, whose
// dependency graph (envoy go-control-plane, inference extensions, ...)
// and replace directives are far too heavy a price for six small structs.
// See docs/agentgateway-extproc.md for the research snapshot this copy is
// based on; re-verify against upstream before extending it.
//
// Only the fields this controller actually sets are declared. Server-side
// apply makes that safe: fields absent from these structs are simply never
// part of the applied document, so values other field managers own are
// left untouched.
//
// +kubebuilder:object:generate=true
// +groupName=agentgateway.dev
package agentgatewayapi

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// GroupVersion is the group/version of the vendored AgentgatewayPolicy API.
var GroupVersion = schema.GroupVersion{Group: "agentgateway.dev", Version: "v1alpha1"}

// SchemeBuilder registers the vendored types with a runtime.Scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(func(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &AgentgatewayPolicy{}, &AgentgatewayPolicyList{})
	metav1.AddToGroupVersion(s, GroupVersion)

	return nil
})

// AddToScheme adds the vendored types to a runtime.Scheme.
var AddToScheme = SchemeBuilder.AddToScheme

// LocalPolicyTargetReference selects one same-namespace object by group,
// kind, and name. The object must be in the same namespace as the policy.
type LocalPolicyTargetReference struct {
	// Group is the API group of the target resource.
	Group gatewayv1.Group `json:"group"`

	// Kind is the API kind of the target resource, such as Gateway or
	// HTTPRoute.
	Kind gatewayv1.Kind `json:"kind"`

	// Name is the name of the target resource.
	Name gatewayv1.ObjectName `json:"name"`
}

// LocalPolicyTargetReferenceWithSectionName selects one same-namespace
// object by group, kind, name, and, optionally, sectionName.
type LocalPolicyTargetReferenceWithSectionName struct {
	LocalPolicyTargetReference `json:",inline"`

	// SectionName is the named section of the target resource.
	// +optional
	SectionName *gatewayv1.SectionName `json:"sectionName,omitempty"`
}

// BodySendMode selects how HTTP bodies are delivered to the external
// processor.
type BodySendMode string

const (
	// BodySendModeNone skips the body phase entirely.
	BodySendModeNone BodySendMode = "None"

	// BodySendModeFullDuplexStreamed streams the body to the processor
	// with no size cap (agentgateway's own default).
	BodySendModeFullDuplexStreamed BodySendMode = "FullDuplexStreamed"
)

// HeaderSendMode selects whether a header phase is sent to the external
// processor.
type HeaderSendMode string

const (
	// HeaderSendModeSend sends the header phase.
	HeaderSendModeSend HeaderSendMode = "Send"

	// HeaderSendModeSkip skips the header phase.
	HeaderSendModeSkip HeaderSendMode = "Skip"
)

// TrailerSendMode selects whether a trailer phase is sent to the external
// processor.
type TrailerSendMode string

const (
	// TrailerSendModeSkip skips the trailer phase.
	TrailerSendModeSkip TrailerSendMode = "Skip"

	// TrailerSendModeSend sends the trailer phase.
	TrailerSendModeSend TrailerSendMode = "Send"
)

// ProcessingOptions configures the external processor's request and
// response phase settings.
type ProcessingOptions struct {
	// +optional
	RequestBodyMode *BodySendMode `json:"requestBodyMode,omitempty"`

	// +optional
	ResponseBodyMode *BodySendMode `json:"responseBodyMode,omitempty"`

	// +optional
	RequestHeaderMode *HeaderSendMode `json:"requestHeaderMode,omitempty"`

	// +optional
	ResponseHeaderMode *HeaderSendMode `json:"responseHeaderMode,omitempty"`

	// +optional
	RequestTrailerMode *TrailerSendMode `json:"requestTrailerMode,omitempty"`

	// +optional
	ResponseTrailerMode *TrailerSendMode `json:"responseTrailerMode,omitempty"`
}

// ExtProc points traffic at an external processor server.
type ExtProc struct {
	// BackendRef is the external processor server to reach. Supported
	// types: Service and Backend.
	// +optional
	BackendRef *gatewayv1.BackendObjectReference `json:"backendRef,omitempty"`

	// ProcessingOptions configures how request and response phases are
	// sent to ext_proc.
	// +optional
	ProcessingOptions *ProcessingOptions `json:"processingOptions,omitempty"`
}

// ExtProcOrConditional is the extProc policy body. The upstream type also
// carries a `conditional` list this controller never sets; it is omitted
// here (see the package doc comment on why that is safe under server-side
// apply).
type ExtProcOrConditional struct {
	ExtProc `json:",inline"`
}

// Traffic holds the traffic-phase policies. The upstream type has many
// more fields; only extProc is vendored.
type Traffic struct {
	// ExtProc is the external processing configuration for the policy.
	// +optional
	ExtProc *ExtProcOrConditional `json:"extProc,omitempty"`
}

// AgentgatewayPolicySpec is the desired policy configuration. The upstream
// spec also supports targetSelectors, strategy, frontend, and backend;
// only the fields this controller generates are vendored.
type AgentgatewayPolicySpec struct {
	// TargetRefs are the target resources to attach the policy to.
	// +optional
	TargetRefs []LocalPolicyTargetReferenceWithSectionName `json:"targetRefs,omitempty"`

	// Traffic holds traffic-phase policies (extProc).
	// +optional
	Traffic *Traffic `json:"traffic,omitempty"`
}

// +kubebuilder:object:root=true

// AgentgatewayPolicy attaches agentgateway data-plane policies (here:
// ext_proc wiring) to a Gateway/HTTPRoute in the same namespace.
type AgentgatewayPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired policy configuration.
	Spec AgentgatewayPolicySpec `json:"spec"`
}

// +kubebuilder:object:root=true

// AgentgatewayPolicyList contains a list of AgentgatewayPolicy.
type AgentgatewayPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AgentgatewayPolicy `json:"items"`
}

var _ runtime.Object = &AgentgatewayPolicy{}
