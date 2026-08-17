package config

import (
	"errors"
	"sort"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
)

// Snapshot is an immutable, compiled view of a Config: the coraza.WAF
// engines built from Directives, plus the Routes needed to select one for a
// given request. A Snapshot is safe for concurrent reads from multiple
// goroutines; producing a new one (via Compile) never mutates an existing
// Snapshot in place, so the processor server can swap its active Snapshot
// atomically on config reload without holding a lock across request
// handling (see internal/processor/server.go).
type Snapshot struct {
	engines map[string]coraza.WAF
	// exact maps an exact Host value to its routes, each sorted by
	// descending PathPrefix length so the first match is always the
	// longest (most specific) one.
	exact map[string][]Route
	// wildcard holds every route whose Host is a "*.<suffix>" pattern,
	// sorted by descending suffix length (more specific subdomain first),
	// then by descending PathPrefix length.
	wildcard []Route
	// catchAll holds every route whose Host is exactly "*", sorted by
	// descending PathPrefix length.
	catchAll []Route
}

// newSnapshot builds a Snapshot from compiled engines and the routes that
// reference them. Routes are partitioned by host-matching strategy (see
// Match) and sorted so each lookup is a simple first-match-wins scan.
func newSnapshot(engines map[string]coraza.WAF, routes []Route) *Snapshot {
	exact := make(map[string][]Route)

	var wildcard, catchAll []Route

	for _, route := range routes {
		switch {
		case route.Host == "*":
			catchAll = append(catchAll, route)
		case strings.HasPrefix(route.Host, "*."):
			wildcard = append(wildcard, route)
		default:
			exact[route.Host] = append(exact[route.Host], route)
		}
	}

	for host, hostRoutes := range exact {
		exact[host] = sortByPathPrefixDesc(hostRoutes)
	}

	sort.SliceStable(wildcard, func(i, j int) bool {
		if len(wildcard[i].Host) != len(wildcard[j].Host) {
			return len(wildcard[i].Host) > len(wildcard[j].Host)
		}

		return len(wildcard[i].PathPrefix) > len(wildcard[j].PathPrefix)
	})

	return &Snapshot{
		engines:  engines,
		exact:    exact,
		wildcard: wildcard,
		catchAll: sortByPathPrefixDesc(catchAll),
	}
}

func sortByPathPrefixDesc(routes []Route) []Route {
	sorted := make([]Route, len(routes))
	copy(sorted, routes)
	sort.SliceStable(sorted, func(i, j int) bool {
		return len(sorted[i].PathPrefix) > len(sorted[j].PathPrefix)
	})

	return sorted
}

// Match resolves the WAF engine that protects the given host+path, following
// this host lookup order (see docs/processor.md for the full rationale):
//
//  1. an exact :authority match
//  2. the same host with any ":port" suffix stripped, still matched
//     exactly
//  3. a wildcard host route ("*.<suffix>") against the host, then again
//     against the port-stripped host - the most specific (longest)
//     matching suffix winning over broader ones
//  4. a catch-all host route ("*")
//
// Within whichever of the above matches, the longest matching pathPrefix
// wins. Every exact-host attempt (with and without port) is exhausted
// before any wildcard is considered, and every wildcard attempt before the
// catch-all, so a specific host is never shadowed by a broader rule just
// because of a port suffix.
//
// It returns (nil, false) when no route matches (the caller should treat the
// request as unprotected/CONTINUE), and (nil, true) when a route matches but
// has no WAF engine attached (e.g. a future DLP-only route).
func (s *Snapshot) Match(host, path string) (coraza.WAF, bool) {
	route, routeFound := s.matchRoute(host, path)
	if !routeFound {
		return nil, false
	}

	if route.WAF == nil {
		return nil, true
	}

	return s.engines[route.WAF.EngineKey], true
}

// hostCandidates returns host, then (if different) host with any trailing
// ":port" stripped.
func hostCandidates(host string) []string {
	candidates := []string{host}
	if stripped := stripPort(host); stripped != host {
		candidates = append(candidates, stripped)
	}

	return candidates
}

func (s *Snapshot) matchRoute(host, path string) (Route, bool) {
	candidates := hostCandidates(host)

	for _, h := range candidates {
		for _, route := range s.exact[h] {
			if strings.HasPrefix(path, route.PathPrefix) {
				return route, true
			}
		}
	}

	for _, h := range candidates {
		for _, route := range s.wildcard {
			// "*.<suffix>" matches a strict subdomain of suffix (e.g.
			// "*.example.com" matches "shop.example.com" but not
			// "example.com" itself), mirroring Gateway API hostname
			// matching.
			suffix := route.Host[1:]
			if !strings.HasSuffix(h, suffix) || len(h) == len(suffix) {
				continue
			}

			if strings.HasPrefix(path, route.PathPrefix) {
				return route, true
			}
		}
	}

	for _, route := range s.catchAll {
		if strings.HasPrefix(path, route.PathPrefix) {
			return route, true
		}
	}

	return Route{}, false
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

// stripPort removes a trailing ":<port>" from an authority/Host header
// value, if present. IPv6 literals (e.g. "[::1]:8080") are left alone unless
// the colon comes after the closing "]".
func stripPort(host string) string {
	bracket := strings.LastIndexByte(host, ']')
	idx := strings.LastIndexByte(host, ':')
	if idx == -1 || idx < bracket {
		return host
	}

	return host[:idx]
}
