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
	engines := map[string]coraza.WAF{"default": engineDefault, "api": engineAPI}

	routes := []Route{
		{Host: "example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "default"}},
		{Host: "example.com", PathPrefix: "/api", WAF: &WAFRef{EngineKey: "api"}},
		{Host: "no-waf.example.com", PathPrefix: "/"},
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
			name:      "unknown host has no match",
			host:      "unknown.example.com",
			path:      "/",
			wantMatch: false,
		},
		{
			name:       "route without waf ref matches but has no engine",
			host:       "no-waf.example.com",
			path:       "/",
			wantMatch:  true,
			wantEngine: nil,
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
