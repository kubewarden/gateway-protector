package config

import (
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
		Routes: []Route{
			{Host: "example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "blocklist"}},
		},
	}

	require.NoError(t, Validate(cfg))

	snapshot, err := Compile(cfg, nil)
	require.NoError(t, err)

	waf, matched := snapshot.Match("example.com", "/")
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
		Routes: []Route{
			{Host: "example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "crs"}},
		},
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
		Routes: []Route{
			{Host: "on.example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "body-on"}},
			{Host: "off.example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "body-off"}},
		},
	}

	require.NoError(t, Validate(cfg))

	snapshot, err := Compile(cfg, nil)
	require.NoError(t, err)

	runRequest := func(t *testing.T, host string) *ctypes.Interruption {
		t.Helper()

		waf, matched := snapshot.Match(host, "/")
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
		interruption := runRequest(t, "on.example.com")
		require.NotNil(t, interruption)
		assert.Equal(t, 2000, interruption.RuleID)
	})

	t.Run("no SecRequestBodyAccess directive leaves the body uninspected", func(t *testing.T) {
		assert.Nil(t, runRequest(t, "off.example.com"))
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
// active Snapshot and calls Match before creating a transaction, so if a
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
		Routes: []Route{
			{Host: "example.com", PathPrefix: "/", WAF: &WAFRef{EngineKey: "blocklist"}},
		},
	}

	require.NoError(t, Validate(cfg))

	snapshot, err := Compile(cfg, nil)
	require.NoError(t, err)

	waf, matched := snapshot.Match("example.com", "/")
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
