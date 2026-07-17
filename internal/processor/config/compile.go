package config

import (
	"fmt"
	"log/slog"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
)

// rootFS is the filesystem SecLang "Include" directives resolve against: the
// embedded OWASP Core Rule Set (as "@owasp_crs/...", "@coraza.conf-recommended",
// "@crs-setup.conf.example" - see the coraza-coreruleset README) merged with
// the OS filesystem for any local/custom includes.
var rootFS = mergefs.Merge(coreruleset.FS, mergefsio.OSFS)

// Compile builds one coraza.WAF engine per entry in cfg.Directives, keyed by
// the same engine key, and returns a Snapshot combining them with cfg.Routes.
// The caller is expected to have already run Validate. Matched-rule logging
// is written to logger; a nil logger defaults to [slog.Default].
//
// Body inspection (whether request/response bodies are buffered at all, and
// the size limits for doing so) is deliberately left to each engine's own
// SecLang directives (SecRequestBodyAccess/SecResponseBodyAccess and their
// *Limit/*InMemoryLimit counterparts) rather than being forced on
// programmatically here. Coraza applies directives before any programmatic
// WAFConfig settings (see coraza/v3's NewWAF), so a hardcoded
// WithRequestBodyAccess()/WithRequestBodyInMemoryLimit() call here would
// silently override an engine's own directives (e.g. one that opts out with
// SecRequestBodyAccess Off, or a future engine compiled without CRS at all
// for a route that has no need to buffer bodies). @coraza.conf-recommended
// already enables both with sane limits for CRS-based engines; this is also
// where WAFPolicy.spec.requestBody/responseBody (see
// api/v1alpha1.WAFBodyInspectionSpec) is expected to land once the
// controller renders this config as directives instead of it being
// hand-authored (see docs/processor.md).
func Compile(cfg *Config, logger *slog.Logger) (*Snapshot, error) {
	if logger == nil {
		logger = slog.Default()
	}

	engines := make(map[string]coraza.WAF, len(cfg.Directives))

	for engineKey, directives := range cfg.Directives {
		wafConfig := coraza.NewWAFConfig().
			WithRootFS(rootFS).
			WithErrorCallback(newErrorCallback(logger, engineKey)).
			WithDirectives(directives)

		waf, err := coraza.NewWAF(wafConfig)
		if err != nil {
			return nil, fmt.Errorf("engine %q: failed to compile directives: %w", engineKey, err)
		}

		engines[engineKey] = waf
	}

	return newSnapshot(engines, cfg.Routes), nil
}

// newErrorCallback builds a Coraza error callback that logs matched rules,
// tagged with the engine key that triggered them.
func newErrorCallback(logger *slog.Logger, engineKey string) func(ctypes.MatchedRule) {
	return func(match ctypes.MatchedRule) {
		rule := match.Rule()

		attrs := []any{
			slog.String("engine_key", engineKey),
			slog.String("transaction_id", match.TransactionID()),
			slog.String("client_ip", match.ClientIPAddress()),
			slog.String("uri", match.URI()),
			slog.Int("rule_id", rule.ID()),
			slog.String("rule_file", rule.File()),
			slog.Int("rule_line", rule.Line()),
			slog.String("severity", rule.Severity().String()),
			slog.String("message", match.Message()),
		}

		msg := "WAF rule triggered"

		switch rule.Severity() {
		case ctypes.RuleSeverityEmergency, ctypes.RuleSeverityAlert, ctypes.RuleSeverityCritical, ctypes.RuleSeverityError:
			logger.Error(msg, attrs...)
		case ctypes.RuleSeverityWarning:
			logger.Warn(msg, attrs...)
		case ctypes.RuleSeverityNotice, ctypes.RuleSeverityInfo, ctypes.RuleSeverityDebug, ctypes.RuleSeverityUnset:
			logger.Info(msg, attrs...)
		default:
			logger.Error(msg, attrs...)
		}
	}
}
