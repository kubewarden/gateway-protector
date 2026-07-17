package config

import (
	"sort"
	"strings"

	"github.com/corazawaf/coraza/v3"
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
	// routes is sorted by descending PathPrefix length so the first match
	// for a given host is always the longest (most specific) one.
	routes []Route
}

// newSnapshot builds a Snapshot from compiled engines and the routes that
// reference them. Routes are copied and sorted so Match can do a simple
// first-match-wins scan.
func newSnapshot(engines map[string]coraza.WAF, routes []Route) *Snapshot {
	sorted := make([]Route, len(routes))
	copy(sorted, routes)
	sort.SliceStable(sorted, func(i, j int) bool {
		return len(sorted[i].PathPrefix) > len(sorted[j].PathPrefix)
	})

	return &Snapshot{engines: engines, routes: sorted}
}

// Match resolves the WAF engine that protects the given host+path, following
// this host lookup order (see docs/processor.md for the full rationale):
// exact :authority match, then the same host with any ":port" suffix
// stripped. Among routes for the matched host, the longest matching
// pathPrefix wins.
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

func (s *Snapshot) matchRoute(host, path string) (Route, bool) {
	if route, routeFound := s.matchRouteForHost(host, path); routeFound {
		return route, true
	}

	if strippedHost := stripPort(host); strippedHost != host {
		if route, routeFound := s.matchRouteForHost(strippedHost, path); routeFound {
			return route, true
		}
	}

	return Route{}, false
}

func (s *Snapshot) matchRouteForHost(host, path string) (Route, bool) {
	for _, route := range s.routes {
		if route.Host != host {
			continue
		}
		if strings.HasPrefix(path, route.PathPrefix) {
			return route, true
		}
	}
	return Route{}, false
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
