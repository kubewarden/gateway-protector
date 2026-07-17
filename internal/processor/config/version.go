package config

import "runtime/debug"

// crsModulePath is the Go module providing the embedded OWASP Core Rule Set
// (see rootFS in compile.go). The module's tag tracks the CRS release it
// vendors (e.g. module v4.25.0 ships CRS 4.25.0).
const crsModulePath = "github.com/corazawaf/coraza-coreruleset/v4"

// unknownCRSVersion is returned when the embedded CRS version can't be
// determined.
const unknownCRSVersion = "unknown"

// EmbeddedCRSVersion returns the version of the OWASP Core Rule Set baked
// into this binary, read from the Go module's build info (populated by the
// toolchain for any module-built binary - no build-system plumbing
// required). Returns "unknown" if build info isn't available (e.g. a
// binary built without module mode) or the dependency can't be found.
func EmbeddedCRSVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return unknownCRSVersion
	}

	return crsVersionFromBuildInfo(info)
}

// crsVersionFromBuildInfo scans info.Deps for the coreruleset module,
// returning its version, or unknownCRSVersion if it isn't found.
func crsVersionFromBuildInfo(info *debug.BuildInfo) string {
	for _, dep := range info.Deps {
		if dep.Path == crsModulePath {
			return dep.Version
		}
	}

	return unknownCRSVersion
}
