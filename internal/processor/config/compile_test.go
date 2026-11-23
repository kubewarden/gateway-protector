package config

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileAndBlock(t *testing.T) {
	cfg := &Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403,msg:'blocked by test rule'"` + "\n",
		},
		SchemaVersion: SchemaVersion,
		Bindings:      []Binding{gatewayBinding("gw", "blocklist")},
	}

	require.NoError(t, Validate(cfg))

	snapshot, err := Compile(cfg, nil)
	require.NoError(t, err)

	waf, matched := snapshot.Resolve(gatewayIdentity("gw"))
	require.True(t, matched)
	require.NotNil(t, waf)

	t.Run("clean request is not blocked", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.ProcessURI("/?test=clean", "GET", "HTTP/1.1")
		assert.Nil(t, tx.ProcessRequestHeaders())
	})

	t.Run("malicious request is blocked", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.ProcessURI("/?test=malicious", "GET", "HTTP/1.1")
		interruption := tx.ProcessRequestHeaders()
		require.NotNil(t, interruption)
		assert.Equal(t, 1000, interruption.RuleID)
		assert.Equal(t, 403, interruption.Status)
	})
}

func TestCompileInvalidDirectives(t *testing.T) {
	cfg := &Config{
		Directives: map[string]string{
			"broken": "ThisIsNotAValidSecLangDirective",
		},
	}

	_, err := Compile(cfg, nil)
	require.Error(t, err)
}

func TestCompileWithCoreRuleSet(t *testing.T) {
	cfg := &Config{
		Directives: map[string]string{
			"crs": "Include @coraza.conf-recommended\n" +
				"Include @crs-setup.conf.example\n" +
				"Include @owasp_crs/*.conf\n",
		},
		SchemaVersion: SchemaVersion,
		Bindings:      []Binding{gatewayBinding("gw", "crs")},
	}

	require.NoError(t, Validate(cfg))

	_, err := Compile(cfg, nil)
	require.NoError(t, err)
}

// TestCompileRequestBodyAccessIsDirectiveDriven locks in that Compile does
// not force request body buffering on programmatically: an engine only
// inspects the request body if its own SecLang directives say so
// (SecRequestBodyAccess On), matching Coraza/ModSecurity's own default
// (access off unless a directive enables it). See the doc comment on
// Compile for why this must not be hardcoded via WithRequestBodyAccess().
//
// The rule matches ARGS_POST, populated by Coraza's URLENCODED body
// processor (selected via the request's Content-Type) - this is the
// realistic way rules (including CRS) inspect POST bodies, and exactly what
// SecRequestBodyAccess gates: without it, Coraza skips body parsing
// entirely and ARGS_POST is never populated, regardless of Content-Type.
func TestCompileRequestBodyAccessIsDirectiveDriven(t *testing.T) {
	const bodyRule = `SecRule ARGS_POST:field "@contains malicious" "id:2000,phase:2,deny,status:403,msg:'body blocked'"` + "\n"

	cfg := &Config{
		Directives: map[string]string{
			"body-on":  "SecRuleEngine On\nSecRequestBodyAccess On\n" + bodyRule,
			"body-off": "SecRuleEngine On\n" + bodyRule,
		},
		SchemaVersion: SchemaVersion,
		Bindings: []Binding{
			gatewayBinding("on-gw", "body-on"),
			gatewayBinding("off-gw", "body-off"),
		},
	}

	require.NoError(t, Validate(cfg))

	snapshot, err := Compile(cfg, nil)
	require.NoError(t, err)

	runRequest := func(t *testing.T, gateway string) *ctypes.Interruption {
		t.Helper()

		waf, matched := snapshot.Resolve(gatewayIdentity(gateway))
		require.True(t, matched)
		require.NotNil(t, waf)

		tx := waf.NewTransaction()
		defer tx.Close()

		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		tx.ProcessURI("/", "POST", "HTTP/1.1")
		require.Nil(t, tx.ProcessRequestHeaders())

		body := []byte("field=this-is-malicious")
		interruption, _, err := tx.WriteRequestBody(body)
		require.NoError(t, err)
		if interruption != nil {
			return interruption
		}

		interruption, err = tx.ProcessRequestBody()
		require.NoError(t, err)
		return interruption
	}

	t.Run("SecRequestBodyAccess On inspects the body", func(t *testing.T) {
		interruption := runRequest(t, "on-gw")
		require.NotNil(t, interruption)
		assert.Equal(t, 2000, interruption.RuleID)
	})

	t.Run("no SecRequestBodyAccess directive leaves the body uninspected", func(t *testing.T) {
		assert.Nil(t, runRequest(t, "off-gw"))
	})
}

// TestSnapshotCloseThenNewTransactionStillWorks is a regression test for the
// safety assumption Server.SetSnapshot relies on (see server.go): closing a
// Snapshot's engines (Snapshot.Close, via coraza/v3's experimental.
// WAFCloser) only releases entries in Coraza's process-wide memoize cache
// for compiled regex/aho-corasick patterns - it must not make the engine
// itself unusable. This drives an engine through Close and *then* creates a
// brand-new transaction from it (the other ordering from
// TestServer_SetSnapshot_InFlightRequestSurvivesPreviousSnapshotClose in
// internal/processor/server_test.go, which closes an engine a transaction
// was already created from): the request-headers handler always loads the
// active Snapshot and calls Resolve before creating a transaction, so if a
// config reload's SetSnapshot races ahead and closes the Snapshot a handler
// is about to use, the transaction it creates afterward must still evaluate
// rules correctly.
//
// Uses a @rx rule specifically (rather than @streq, as in TestCompileAndBlock)
// because @rx is one of the operators that actually goes through Coraza's
// memoizer (see coraza/v3's internal/operators/rx.go), so this exercises the
// exact cache Close releases, not just an unrelated code path.
func TestSnapshotCloseThenNewTransactionStillWorks(t *testing.T) {
	cfg := &Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@rx ^malicious$" "id:1000,phase:1,deny,status:403,msg:'blocked by test rule'"` + "\n",
		},
		SchemaVersion: SchemaVersion,
		Bindings:      []Binding{gatewayBinding("gw", "blocklist")},
	}

	require.NoError(t, Validate(cfg))

	snapshot, err := Compile(cfg, nil)
	require.NoError(t, err)

	waf, matched := snapshot.Resolve(gatewayIdentity("gw"))
	require.True(t, matched)
	require.NotNil(t, waf)

	// Close the Snapshot's engines before creating any transaction from
	// them - the reverse ordering of TestCompileAndBlock, and the one
	// in-flight requests never hit today but a config-reload race could.
	require.NoError(t, snapshot.Close())

	t.Run("clean request is not blocked", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.ProcessURI("/?test=clean", "GET", "HTTP/1.1")
		assert.Nil(t, tx.ProcessRequestHeaders())
	})

	t.Run("malicious request is still blocked after Close", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.ProcessURI("/?test=malicious", "GET", "HTTP/1.1")
		interruption := tx.ProcessRequestHeaders()
		require.NotNil(t, interruption)
		assert.Equal(t, 1000, interruption.RuleID)
		assert.Equal(t, 403, interruption.Status)
	})
}

// TestCompileWithMatchedRuleWriter is a regression test for
// WithMatchedRuleWriter: a matched rule must produce a ModSecurity-format
// ("ErrorLog") line - carrying `[id "NNN"]` for the rule that fired - on
// the configured writer, in addition to (not instead of) the normal
// structured slog line. This is the format go-ftw (see test/ftw) and
// ModSecurity-log-aware tooling expect.
func TestCompileWithMatchedRuleWriter(t *testing.T) {
	cfg := &Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403,log,msg:'blocked by test rule'"` + "\n",
		},
		SchemaVersion: SchemaVersion,
		Bindings:      []Binding{gatewayBinding("gw", "blocklist")},
	}

	require.NoError(t, Validate(cfg))

	var buf bytes.Buffer

	snapshot, err := Compile(cfg, nil, WithMatchedRuleWriter(&buf))
	require.NoError(t, err)

	waf, matched := snapshot.Resolve(gatewayIdentity("gw"))
	require.True(t, matched)
	require.NotNil(t, waf)

	tx := waf.NewTransaction()
	defer tx.Close()

	tx.ProcessURI("/?test=malicious", "GET", "HTTP/1.1")
	interruption := tx.ProcessRequestHeaders()
	require.NotNil(t, interruption)

	assert.Contains(t, buf.String(), `[id "1000"]`)
}

// TestCompileWithMatchedRuleWriter_ConcurrentEnginesAreSafe exercises
// WithMatchedRuleWriter's concurrency contract: a single writer shared
// across multiple engines (and, within one engine, concurrent
// transactions) must not corrupt interleaved writes - see syncWriter. Runs
// under `go test -race`.
func TestCompileWithMatchedRuleWriter_ConcurrentEnginesAreSafe(t *testing.T) {
	const rule = `SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403,log,msg:'blocked by test rule'"` + "\n"

	cfg := &Config{
		Directives: map[string]string{
			"engine-a": "SecRuleEngine On\n" + rule,
			"engine-b": "SecRuleEngine On\n" + rule,
		},
		SchemaVersion: SchemaVersion,
		Bindings: []Binding{
			gatewayBinding("engine-a-gw", "engine-a"),
			gatewayBinding("engine-b-gw", "engine-b"),
		},
	}

	require.NoError(t, Validate(cfg))

	var buf syncBuffer

	snapshot, err := Compile(cfg, nil, WithMatchedRuleWriter(&buf))
	require.NoError(t, err)

	trigger := func(gateway string) {
		waf, matched := snapshot.Resolve(gatewayIdentity(gateway))
		require.True(t, matched)

		tx := waf.NewTransaction()
		defer tx.Close()

		tx.ProcessURI("/?test=malicious", "GET", "HTTP/1.1")
		tx.ProcessRequestHeaders()
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(2)
		go func() { defer wg.Done(); trigger("engine-a-gw") }()
		go func() { defer wg.Done(); trigger("engine-b-gw") }()
	}
	wg.Wait()

	assert.Equal(t, 40, strings.Count(buf.String(), `[id "1000"]`))
}

// syncBuffer wraps bytes.Buffer with a mutex so the race detector doesn't
// flag TestCompileWithMatchedRuleWriter_ConcurrentEnginesAreSafe's own
// reads (String()) racing with concurrent Write calls - a test-harness
// concern distinct from what's under test (Compile's internal syncWriter,
// which serializes the writes themselves).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.buf.String()
}
