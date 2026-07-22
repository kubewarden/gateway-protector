package config

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeWAF is a minimal coraza.WAF implementation used to assert engine
// identity (by pointer) without compiling a real Coraza engine.
type fakeWAF struct{ name string }

func (f *fakeWAF) NewTransaction() ctypes.Transaction             { return nil }
func (f *fakeWAF) NewTransactionWithID(string) ctypes.Transaction { return nil }

func TestSnapshotMatch(t *testing.T) {
	engineDefault := &fakeWAF{name: "default"}
	engineAPI := &fakeWAF{name: "api"}
	engineAPIv1 := &fakeWAF{name: "api-v1"}
	engineWildcard := &fakeWAF{name: "wildcard"}
	engineCatchAll := &fakeWAF{name: "catch-all"}
	engines := map[string]coraza.WAF{
		"default":   engineDefault,
		"api":       engineAPI,
		"api-v1":    engineAPIv1,
		"wildcard":  engineWildcard,
		"catch-all": engineCatchAll,
	}

	routes := []Route{
		{Host: "example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "default"}},
		{Host: "example.com", PathPrefix: "/api", WAF: &WAFRef{EngineKey: "api"}},
		{Host: "no-waf.example.com", PathPrefix: "/"},
		{Host: "api.example.com", PathPrefix: "/v1", WAF: &WAFRef{EngineKey: "api-v1"}},
		{Host: "*.example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "wildcard"}},
		{Host: "*", PathPrefix: "/", WAF: &WAFRef{EngineKey: "catch-all"}},
	}

	snapshot := newSnapshot(engines, routes)

	tests := []struct {
		name       string
		host       string
		path       string
		wantMatch  bool
		wantEngine coraza.WAF
	}{
		{
			name:       "longest prefix wins",
			host:       "example.com",
			path:       "/api/orders",
			wantMatch:  true,
			wantEngine: engineAPI,
		},
		{
			name:       "falls back to shorter prefix",
			host:       "example.com",
			path:       "/other",
			wantMatch:  true,
			wantEngine: engineDefault,
		},
		{
			name:       "port is stripped when no exact match",
			host:       "example.com:8443",
			path:       "/other",
			wantMatch:  true,
			wantEngine: engineDefault,
		},
		{
			name:       "wildcard matches a subdomain with no exact route",
			host:       "shop.example.com",
			path:       "/",
			wantMatch:  true,
			wantEngine: engineWildcard,
		},
		{
			name:       "exact match wins over wildcard for the bare suffix",
			host:       "no-waf.example.com",
			path:       "/",
			wantMatch:  true,
			wantEngine: nil,
		},
		{
			name:       "exact match wins over wildcard when both apply",
			host:       "example.com",
			path:       "/unrouted",
			wantMatch:  true,
			wantEngine: engineDefault,
		},
		{
			name:       "catch-all matches any other host",
			host:       "unknown.example.org",
			path:       "/",
			wantMatch:  true,
			wantEngine: engineCatchAll,
		},
		{
			name:       "exact host's own path wins over the wildcard it also matches",
			host:       "api.example.com",
			path:       "/v1/users",
			wantMatch:  true,
			wantEngine: engineAPIv1,
		},
		{
			name:       "exact host found but its path misses: falls through to the wildcard tier",
			host:       "api.example.com",
			path:       "/other",
			wantMatch:  true,
			wantEngine: engineWildcard,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf, matched := snapshot.Match(tt.host, tt.path)
			require.Equal(t, tt.wantMatch, matched)
			if !matched {
				return
			}
			if tt.wantEngine == nil {
				assert.Nil(t, waf)
			} else {
				assert.Same(t, tt.wantEngine, waf)
			}
		})
	}
}

func TestSnapshotWildcardExcludesBareSuffix(t *testing.T) {
	engineWildcard := &fakeWAF{name: "wildcard"}
	engines := map[string]coraza.WAF{"wildcard": engineWildcard}

	routes := []Route{
		{Host: "*.example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "wildcard"}},
	}

	snapshot := newSnapshot(engines, routes)

	_, matched := snapshot.Match("example.com", "/")
	assert.False(t, matched, "*.example.com must not match the bare suffix example.com")

	waf, matched := snapshot.Match("shop.example.com", "/")
	require.True(t, matched)
	assert.Same(t, engineWildcard, waf)
}

func TestSnapshotMatchWildcardSpecificity(t *testing.T) {
	engineBroad := &fakeWAF{name: "broad"}
	engineNarrow := &fakeWAF{name: "narrow"}
	engines := map[string]coraza.WAF{"broad": engineBroad, "narrow": engineNarrow}

	routes := []Route{
		{Host: "*.example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "broad"}},
		{Host: "*.internal.example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "narrow"}},
	}

	snapshot := newSnapshot(engines, routes)

	waf, matched := snapshot.Match("api.internal.example.com", "/")
	require.True(t, matched)
	assert.Same(t, engineNarrow, waf, "the more specific wildcard suffix should win")

	waf, matched = snapshot.Match("shop.example.com", "/")
	require.True(t, matched)
	assert.Same(t, engineBroad, waf)
}

func TestSnapshotNoMatch(t *testing.T) {
	t.Run("empty snapshot", func(t *testing.T) {
		snapshot := newSnapshot(map[string]coraza.WAF{}, nil)

		_, matched := snapshot.Match("unknown.example.com", "/")
		assert.False(t, matched)
	})

	// A populated snapshot with no catch-all route: every case below must
	// exhaust the exact, port-stripped, and wildcard tiers and still come
	// up empty, rather than the presence of *some* routes accidentally
	// producing a match.
	engineExact := &fakeWAF{name: "exact"}
	engineWildcard := &fakeWAF{name: "wildcard"}
	engines := map[string]coraza.WAF{"exact": engineExact, "wildcard": engineWildcard}

	routes := []Route{
		{Host: "example.com", PathPrefix: "/api", WAF: &WAFRef{EngineKey: "exact"}},
		{Host: "*.example.com", PathPrefix: "/shop", WAF: &WAFRef{EngineKey: "wildcard"}},
	}

	snapshot := newSnapshot(engines, routes)

	tests := []struct {
		name string
		host string
		path string
	}{
		{
			name: "unknown host matches no exact or wildcard route",
			host: "unknown.example.org",
			path: "/",
		},
		{
			name: "unknown host with a port still misses after stripping it",
			host: "unknown.example.org:8443",
			path: "/",
		},
		{
			name: "exact host found, but no route's path matches",
			host: "example.com",
			path: "/other",
		},
		{
			name: "wildcard-matched host found, but no route's path matches",
			host: "shop.example.com",
			path: "/other",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, matched := snapshot.Match(tt.host, tt.path)
			assert.False(t, matched)
		})
	}
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"example.com", "example.com"},
		{"example.com:8443", "example.com"},
		{"[::1]", "[::1]"},
		{"[::1]:8443", "[::1]"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			assert.Equal(t, tt.want, stripPort(tt.host))
		})
	}
}
