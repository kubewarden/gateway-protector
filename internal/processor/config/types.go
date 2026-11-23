// Package config parses and compiles the processor's data-plane configuration:
// the Coraza/SecLang directive blocks, keyed by an opaque "engine key" used to
// deduplicate identical compiled directive blocks across policies, plus the
// bindings that attach each engine to a Gateway API attachment point (a
// Gateway, one of its listeners, an HTTPRoute, or one of its rules).
//
// The controller renders this from WAFPolicy/WAFRuleSet Kubernetes objects
// (see api/v1alpha1 and internal/controller/processorconfig) and pushes it to
// the processor as canonical JSON over the config stream (see
// proto/configstream/v1/config_stream.proto and Subscriber) - see
// docs/processor.md for the full schema reference, matching semantics, and a
// complete example.
package config

import "fmt"

// SchemaVersion is the version of the Config format. Validate rejects a
// Config with any other version, and the processor announces the version it
// accepts when it subscribes to the config stream, so a controller and a
// processor of incompatible versions never misread each other's
// configuration. Version 1 had no schemaVersion field and selected engines
// with a table of hosts and path prefixes; version 2 replaced that table
// with Bindings.
const SchemaVersion = 2

// Binding kinds: the two kinds of object a WAFPolicy can target.
const (
	KindGateway   = "Gateway"
	KindHTTPRoute = "HTTPRoute"
)

// Config is the root of the processor's data-plane configuration.
type Config struct {
	// SchemaVersion must equal the SchemaVersion constant.
	SchemaVersion int `json:"schemaVersion"`

	// Directives maps an engine key to a block of raw Coraza/SecLang
	// directives. Each entry is compiled into its own coraza.WAF engine,
	// keyed by this string. Identical rendered directive blocks are
	// expected to share the same engine key (e.g. a hash of the rendered
	// directives) so that engines get deduplicated in memory instead of
	// compiling one per policy that happens to use the exact same rules.
	Directives map[string]string `json:"directives"`

	// Bindings attaches engines to Gateway API attachment points, one per
	// Accepted WAFPolicy. See Snapshot.Resolve for how a request selects
	// one, and internal/controller/processorconfig.Build's doc comment for
	// why this slice's order is a documented invariant (canonical for the
	// same logical input), not incidental.
	Bindings []Binding `json:"bindings"`
}

// Binding attaches a WAF engine to one Gateway API attachment point: the
// object, and optionally the section, that a WAFPolicy's spec.targetRef
// names.
type Binding struct {
	// Kind is KindGateway or KindHTTPRoute.
	Kind string `json:"kind"`

	// Namespace and Name identify the Gateway or HTTPRoute.
	Namespace string `json:"namespace"`
	Name      string `json:"name"`

	// SectionName narrows the binding to one listener (Kind Gateway) or one
	// named rule (Kind HTTPRoute). Empty means the whole object.
	SectionName string `json:"sectionName,omitempty"`

	// WAF selects the engine that inspects requests/responses resolved to
	// this binding. Nil means the binding claims its attachment point but
	// runs no engine: the controller publishes this for a policy whose
	// directives failed to compile, so that resolution stops here instead
	// of falling back to a less specific policy (see Snapshot.Resolve).
	WAF *WAFRef `json:"waf,omitempty"`
}

// WAFRef references a compiled WAF engine by its Directives key.
type WAFRef struct {
	// EngineKey must match a key in Config.Directives.
	EngineKey string `json:"engineKey"`
}

// AttachmentPoint is what a WAFPolicy targets: a Gateway or an HTTPRoute,
// and optionally one listener or one named rule of it. It identifies a
// binding: the processor looks bindings up by it, and Validate requires it
// to be unique. The controller uses the same type to index the policies
// it builds the bindings from, so the two sides cannot disagree on what
// identifies a target.
type AttachmentPoint struct {
	// Kind is KindGateway or KindHTTPRoute.
	Kind      string
	Namespace string
	Name      string

	// SectionName is the listener name (Kind Gateway) or the rule name
	// (Kind HTTPRoute). Empty means the whole object.
	SectionName string
}

func (p AttachmentPoint) String() string {
	s := fmt.Sprintf("%s %s/%s", p.Kind, p.Namespace, p.Name)
	if p.SectionName != "" {
		s += " section " + p.SectionName
	}

	return s
}

// AttachmentPoint returns the attachment point of b.
func (b Binding) AttachmentPoint() AttachmentPoint {
	return AttachmentPoint{Kind: b.Kind, Namespace: b.Namespace, Name: b.Name, SectionName: b.SectionName}
}
