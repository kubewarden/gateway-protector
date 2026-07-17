package config

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCRSVersionFromBuildInfo(t *testing.T) {
	tests := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{
			name: "coreruleset dependency is found",
			info: &debug.BuildInfo{
				Deps: []*debug.Module{
					{Path: "github.com/some/unrelated/module", Version: "v1.2.3"},
					{Path: crsModulePath, Version: "v4.25.0"},
				},
			},
			want: "v4.25.0",
		},
		{
			name: "coreruleset dependency is absent",
			info: &debug.BuildInfo{
				Deps: []*debug.Module{
					{Path: "github.com/some/unrelated/module", Version: "v1.2.3"},
				},
			},
			want: unknownCRSVersion,
		},
		{
			name: "no dependencies at all",
			info: &debug.BuildInfo{},
			want: unknownCRSVersion,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, crsVersionFromBuildInfo(test.info))
		})
	}
}

func TestEmbeddedCRSVersion(t *testing.T) {
	// EmbeddedCRSVersion relies on the Go toolchain populating build info,
	// which only lists the full dependency graph in binaries built via
	// "go build" (not under "go test"), so this only asserts it returns
	// some non-empty string rather than a specific version - the module
	// scan itself is covered by TestCRSVersionFromBuildInfo above.
	assert.NotEmpty(t, EmbeddedCRSVersion())
}
