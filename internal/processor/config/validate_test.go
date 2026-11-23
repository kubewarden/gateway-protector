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
				SchemaVersion: SchemaVersion,
				Directives:    map[string]string{"a": "SecRuleEngine On"},
				Bindings: []Binding{
					gatewayBinding("gw", "a"),
					{Kind: KindGateway, Namespace: "infra", Name: "gw", SectionName: "http", WAF: &WAFRef{EngineKey: "a"}},
					{Kind: KindHTTPRoute, Namespace: "app", Name: "web", WAF: &WAFRef{EngineKey: "a"}},
					{Kind: KindHTTPRoute, Namespace: "app", Name: "web", SectionName: "health", WAF: &WAFRef{EngineKey: "a"}},
				},
			},
		},
		{
			name: "config with no directives and no bindings is valid",
			cfg:  Config{SchemaVersion: SchemaVersion},
		},
		{
			name:    "config without a schema version is rejected",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name:    "config of another schema version is rejected",
			cfg:     Config{SchemaVersion: SchemaVersion + 1},
			wantErr: true,
		},
		{
			name: "binding without waf ref is allowed",
			cfg: Config{
				SchemaVersion: SchemaVersion,
				Bindings:      []Binding{{Kind: KindHTTPRoute, Namespace: "app", Name: "web"}},
			},
		},
		{
			name: "binding references unknown engine key",
			cfg: Config{
				SchemaVersion: SchemaVersion,
				Directives:    map[string]string{"a": "SecRuleEngine On"},
				Bindings:      []Binding{gatewayBinding("gw", "unknown")},
			},
			wantErr: true,
		},
		{
			name: "empty directive body",
			cfg: Config{
				SchemaVersion: SchemaVersion,
				Directives:    map[string]string{"a": "   "},
			},
			wantErr: true,
		},
		{
			name: "binding with an unsupported kind",
			cfg: Config{
				SchemaVersion: SchemaVersion,
				Bindings:      []Binding{{Kind: "GRPCRoute", Namespace: "app", Name: "web"}},
			},
			wantErr: true,
		},
		{
			name: "binding missing namespace",
			cfg: Config{
				SchemaVersion: SchemaVersion,
				Bindings:      []Binding{{Kind: KindGateway, Name: "gw"}},
			},
			wantErr: true,
		},
		{
			name: "binding missing name",
			cfg: Config{
				SchemaVersion: SchemaVersion,
				Bindings:      []Binding{{Kind: KindGateway, Namespace: "infra"}},
			},
			wantErr: true,
		},
		{
			name: "two bindings for the same attachment point",
			cfg: Config{
				SchemaVersion: SchemaVersion,
				Directives:    map[string]string{"a": "SecRuleEngine On"},
				Bindings: []Binding{
					{Kind: KindHTTPRoute, Namespace: "app", Name: "web", SectionName: "health", WAF: &WAFRef{EngineKey: "a"}},
					{Kind: KindHTTPRoute, Namespace: "app", Name: "web", SectionName: "health"},
				},
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
