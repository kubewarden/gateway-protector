// Package config parses and compiles the processor's data-plane configuration:
// a host+path routing table plus the Coraza/SecLang directive blocks it
// references, keyed by an opaque "engine key" used to deduplicate identical
// compiled directive blocks across policies/routes.
//
// This is a hand-authored YAML file for now; see docs/processor.md for the
// full schema reference, matching semantics, and a complete example. A
// future controller will render this file automatically from
// WAFPolicy/WAFRuleSet Kubernetes objects (see the CRD types under
// api/v1alpha1) instead of it being hand-authored.
package config

// Config is the root of the processor's data-plane configuration file.
type Config struct {
	// Directives maps an engine key to a block of raw Coraza/SecLang
	// directives. Each entry is compiled into its own coraza.WAF engine,
	// keyed by this string. Identical rendered directive blocks are
	// expected to share the same engine key (e.g. a hash of the rendered
	// directives) so that engines get deduplicated in memory instead of
	// compiling one per policy/route that happens to use the exact same
	// rules.
	Directives map[string]string `yaml:"directives"`

	// Routes maps host+pathPrefix pairs to the engine that protects them.
	Routes []Route `yaml:"routes"`
}

// Route associates a host+pathPrefix with the WAF engine that protects it.
type Route struct {
	// Host is matched against the request's :authority/Host header. It is
	// one of:
	//   - an exact hostname (e.g. "shop.example.com")
	//   - a wildcard "*.<suffix>" (e.g. "*.example.com"), matching any
	//     strict subdomain of suffix (not the bare suffix itself)
	//   - the catch-all "*", matching any host
	//
	// An exact match is tried first; if none matches, the port suffix (if
	// any) is stripped and the exact lookup is retried; then the most
	// specific matching wildcard; then the catch-all (see
	// internal/processor/config/snapshot.go for the full lookup order).
	Host string `yaml:"host"`

	// PathPrefix is matched against the request's :path. The longest
	// matching prefix across all routes for the matched host wins.
	PathPrefix string `yaml:"pathPrefix"`

	// WAF selects the engine that inspects requests/responses for this
	// route. Nil means the route has no WAF engine attached: the route is
	// matched (distinct from no route matching at all) but currently does
	// nothing - reserved for a future DLP-only route once response-body
	// inspection/redaction is implemented independently of the WAF engine
	// (see docs/processor.md).
	WAF *WAFRef `yaml:"waf,omitempty"`
}

// WAFRef references a compiled WAF engine by its Directives key.
type WAFRef struct {
	// EngineKey must match a key in Config.Directives.
	EngineKey string `yaml:"engineKey"`
}
