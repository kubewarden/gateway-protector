package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes: []Route{
					{Host: "example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "a"}},
				},
			},
		},
		{
			name:    "no directives",
			cfg:     Config{Routes: []Route{{Host: "example.com", PathPrefix: "/"}}},
			wantErr: true,
		},
		{
			name: "empty directive body",
			cfg: Config{
				Directives: map[string]string{"a": "   "},
			},
			wantErr: true,
		},
		{
			name: "route missing host",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes:     []Route{{PathPrefix: "/"}},
			},
			wantErr: true,
		},
		{
			name: "route missing pathPrefix",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes:     []Route{{Host: "example.com"}},
			},
			wantErr: true,
		},
		{
			name: "route pathPrefix without leading slash",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes:     []Route{{Host: "example.com", PathPrefix: "api"}},
			},
			wantErr: true,
		},
		{
			name: "route references unknown engine key",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes: []Route{
					{Host: "example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "unknown"}},
				},
			},
			wantErr: true,
		},
		{
			name: "route without waf ref is allowed",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes:     []Route{{Host: "example.com", PathPrefix: "/"}},
			},
		},
		{
			name: "wildcard host is allowed",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes:     []Route{{Host: "*.example.com", PathPrefix: "/"}},
			},
		},
		{
			name: "catch-all host is allowed",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes:     []Route{{Host: "*", PathPrefix: "/"}},
			},
		},
		{
			name: "wildcard host with empty suffix is rejected",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes:     []Route{{Host: "*.", PathPrefix: "/"}},
			},
			wantErr: true,
		},
		{
			name: "wildcard host with a second wildcard label is rejected",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes:     []Route{{Host: "*.foo.*.com", PathPrefix: "/"}},
			},
			wantErr: true,
		},
		{
			name: "wildcard not anchored at the start is rejected",
			cfg: Config{
				Directives: map[string]string{"a": "SecRuleEngine On"},
				Routes:     []Route{{Host: "foo*.example.com", PathPrefix: "/"}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(&tt.cfg)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
