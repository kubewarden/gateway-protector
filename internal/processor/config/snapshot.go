package config

import (
	"errors"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
)

// Snapshot is an immutable, compiled view of a Config: the coraza.WAF
// engines built from Directives, plus the Bindings needed to select one for
// a given request. A Snapshot is safe for concurrent reads from multiple
// goroutines; producing a new one (via Compile) never mutates an existing
// Snapshot in place, so the processor server can swap its active Snapshot
// atomically on config reload without holding a lock across request
// handling (see internal/processor/server.go).
type Snapshot struct {
	engines map[string]coraza.WAF
	// bindings maps each bound attachment point to its engine reference.
	// A nil reference is a binding without an engine (see Binding.WAF),
	// distinct from an attachment point that has no binding at all.
	bindings map[AttachmentPoint]*WAFRef
}

// newSnapshot builds a Snapshot from compiled engines and the bindings that
// reference them.
func newSnapshot(engines map[string]coraza.WAF, bindings []Binding) *Snapshot {
	index := make(map[AttachmentPoint]*WAFRef, len(bindings))
	for _, binding := range bindings {
		index[binding.AttachmentPoint()] = binding.WAF
	}

	return &Snapshot{engines: engines, bindings: index}
}

// Resolve returns the WAF engine that protects a request with the given
// identity. It tries these attachment points, most specific first, and
// stops at the first one that has a binding (see docs/processor.md and
// docs/policy-attachment.md):
//
//  1. the HTTPRoute rule (only when the rule has a name)
//  2. the whole HTTPRoute
//  3. the Gateway listener
//  4. the whole Gateway
//
// The two HTTPRoute levels apply only when id.RouteKind is KindHTTPRoute.
//
// It returns (nil, false) when no binding matches: no WAFPolicy covers the
// request, and the caller should let it continue uninspected. It returns
// (nil, true) when the first matching binding has no WAF engine (see
// Binding.WAF): the request also continues uninspected, and no less specific
// binding is tried.
func (s *Snapshot) Resolve(id Identity) (coraza.WAF, bool) {
	for _, point := range id.attachmentPoints() {
		ref, found := s.bindings[point]
		if !found {
			continue
		}

		if ref == nil {
			return nil, true
		}

		return s.engines[ref.EngineKey], true
	}

	return nil, false
}

// Close releases every coraza.WAF engine in this Snapshot that implements
// experimental.WAFCloser, freeing entries those engines own in Coraza's
// process-wide memoize cache for compiled regex/aho-corasick patterns (see
// coraza/v3's experimental package). Engines that don't implement
// WAFCloser (e.g. test fakes) are skipped.
//
// Close is safe to call while other goroutines still hold Coraza
// transactions created from this Snapshot's engines: WAFCloser's contract
// guarantees in-flight transactions are unaffected, since they hold their
// own references to the compiled objects they need - only the shared cache
// entries are released. Errors from individual engines are joined; Close
// still attempts every engine even if an earlier one fails.
func (s *Snapshot) Close() error {
	var errs []error

	for _, waf := range s.engines {
		closer, ok := waf.(experimental.WAFCloser)
		if !ok {
			continue
		}

		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
