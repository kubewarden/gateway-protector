package config

import (
	"fmt"
	"io"
	"log/slog"
	"sync"

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

// compileOptions holds Compile's optional behavior, configured via
// CompileOption values.
type compileOptions struct {
	matchedRuleWriter io.Writer
}

// CompileOption configures optional Compile behavior.
type CompileOption func(*compileOptions)

// WithMatchedRuleWriter additionally writes every matched rule's
// ModSecurity-format log line - coraza's own MatchedRule.ErrorLog(), e.g.
// `[client "10.0.0.1"] Coraza: Access denied ... [id "941100"] ...` - to w,
// one line per match, across every engine Compile builds. w is wrapped in
// an internal mutex, so a single writer (e.g. one file) can safely be
// shared by every engine and concurrent request.
//
// This exists for tooling that understands ModSecurity's log format rather
// than this project's own structured slog lines - most notably go-ftw, the
// CRS regression test runner (see test/ftw), which correlates each test's
// request with the rule IDs this produces to verify the exact rule fired.
// It doubles as a production capability for operators who already run
// ModSecurity-log-aware tooling (fail2ban-style blockers, SIEM parsers):
// unlike the structured slog line ("WAF rule triggered", which carries the
// same information plus engine_key/transaction_id in a different shape),
// this format is a widely-recognized standard on its own. It is opt-in
// (nil by default) precisely because it's a second, differently-shaped
// sink alongside the structured logs, not a replacement for them - see
// cmd/processor's --waf-matched-rules-log flag.
func WithMatchedRuleWriter(w io.Writer) CompileOption {
	return func(o *compileOptions) {
		o.matchedRuleWriter = w
	}
}

// Compile builds one coraza.WAF engine per entry in cfg.Directives, keyed by
// the same engine key, and returns a Snapshot combining them with cfg.Bindings.
// The caller is expected to have already run Validate. Matched-rule logging
// is written to logger; a nil logger defaults to [slog.Default]. See
// CompileOption for optional behavior (e.g. WithMatchedRuleWriter).
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
func Compile(cfg *Config, logger *slog.Logger, opts ...CompileOption) (*Snapshot, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var options compileOptions
	for _, opt := range opts {
		opt(&options)
	}

	var matchedRuleWriter io.Writer
	if options.matchedRuleWriter != nil {
		matchedRuleWriter = &syncWriter{w: options.matchedRuleWriter}
	}

	engines := make(map[string]coraza.WAF, len(cfg.Directives))

	for engineKey, directives := range cfg.Directives {
		wafConfig := coraza.NewWAFConfig().
			WithRootFS(rootFS).
			WithErrorCallback(newErrorCallback(logger, engineKey, matchedRuleWriter)).
			WithDirectives(directives)

		waf, err := coraza.NewWAF(wafConfig)
		if err != nil {
			return nil, fmt.Errorf("engine %q: failed to compile directives: %w", engineKey, err)
		}

		engines[engineKey] = waf
	}

	return newSnapshot(engines, cfg.Bindings), nil
}

// syncWriter serializes concurrent writes to w: multiple engines (and,
// within one engine, multiple concurrent transactions) share the same
// matchedRuleWriter, and [io.Writer]'s contract doesn't guarantee a single
// Write call is safe to use concurrently without one.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, err := s.w.Write(p)
	if err != nil {
		return n, fmt.Errorf("matched-rule writer: %w", err)
	}

	return n, nil
}

// newErrorCallback builds a Coraza error callback that logs matched rules,
// tagged with the engine key that triggered them, and - if
// matchedRuleWriter is non-nil - additionally writes each match's
// ModSecurity-format log line to it (see WithMatchedRuleWriter).
func newErrorCallback(logger *slog.Logger, engineKey string, matchedRuleWriter io.Writer) func(ctypes.MatchedRule) {
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

		if matchedRuleWriter != nil {
			if _, err := io.WriteString(matchedRuleWriter, match.ErrorLog()+"\n"); err != nil {
				logger.Error("Failed to write matched-rule log line", slog.String("engine_key", engineKey), slog.Any("error", err))
			}
		}
	}
}
