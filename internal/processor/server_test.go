package processor

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/kubewarden/gateway-protector/internal/processor/config"
)

const bufSize = 1024 * 1024

// startTestServer starts the processor's Server over an in-memory bufconn
// listener with the given config, returning a connected ext_proc client and
// a cleanup function.
func startTestServer(t *testing.T, cfg *config.Config) envoy_service_ext_proc_v3.ExternalProcessorClient {
	t.Helper()

	require.NoError(t, config.Validate(cfg))
	snapshot, err := config.Compile(cfg, nil)
	require.NoError(t, err)

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(grpcServer, New(snapshot, nil))

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return envoy_service_ext_proc_v3.NewExternalProcessorClient(conn)
}

// rawHeaderValue builds a HeaderValue using the raw_value wire
// representation - what agentgateway itself uses for ordinary headers (see
// handlers.go's headerValue doc comment for why both representations
// matter).
func rawHeaderValue(key, value string) *envoy_config_core_v3.HeaderValue {
	return &envoy_config_core_v3.HeaderValue{Key: key, RawValue: []byte(value)}
}

// stringHeaderValue builds a HeaderValue using the value (string) wire
// representation - what agentgateway uses for the synthetic pseudo-headers
// (:authority, :method, :path, :status) it adds to the ext_proc payload.
func stringHeaderValue(key, value string) *envoy_config_core_v3.HeaderValue {
	return &envoy_config_core_v3.HeaderValue{Key: key, Value: value}
}

func requestHeadersMessage(authority, path string) *envoy_service_ext_proc_v3.ProcessingRequest {
	return &envoy_service_ext_proc_v3.ProcessingRequest{
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &envoy_service_ext_proc_v3.HttpHeaders{
				Headers: &envoy_config_core_v3.HeaderMap{
					Headers: []*envoy_config_core_v3.HeaderValue{
						rawHeaderValue(":authority", authority),
						rawHeaderValue(":method", "GET"),
						rawHeaderValue(":path", path),
						rawHeaderValue(":scheme", "https"),
					},
				},
			},
		},
	}
}

// requestHeadersMessageAgentgatewayEncoding is requestHeadersMessage, but
// using agentgateway's actual wire encoding for pseudo-headers: the `value`
// field, not `raw_value` (see handlers.go's headerValue doc comment).
// Exists to guard against a real bug where reading only raw_value made
// every request look like it was missing pseudo-headers and silently skip
// the WAF, regardless of what SecRule directives were configured.
//
// authority is always "example.com" here (every test config below routes
// that host to a WAF engine), so it's hardcoded rather than taken as a
// parameter.
func requestHeadersMessageAgentgatewayEncoding(path string) *envoy_service_ext_proc_v3.ProcessingRequest {
	return &envoy_service_ext_proc_v3.ProcessingRequest{
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &envoy_service_ext_proc_v3.HttpHeaders{
				Headers: &envoy_config_core_v3.HeaderMap{
					Headers: []*envoy_config_core_v3.HeaderValue{
						stringHeaderValue(":authority", "example.com"),
						stringHeaderValue(":method", "GET"),
						stringHeaderValue(":path", path),
						stringHeaderValue(":scheme", "https"),
					},
				},
			},
		},
	}
}

func requestBodyMessage() *envoy_service_ext_proc_v3.ProcessingRequest {
	return &envoy_service_ext_proc_v3.ProcessingRequest{
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_RequestBody{
			RequestBody: &envoy_service_ext_proc_v3.HttpBody{
				EndOfStream: true,
			},
		},
	}
}

func responseHeadersMessage(statusCode string) *envoy_service_ext_proc_v3.ProcessingRequest {
	return &envoy_service_ext_proc_v3.ProcessingRequest{
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &envoy_service_ext_proc_v3.HttpHeaders{
				Headers: &envoy_config_core_v3.HeaderMap{
					Headers: []*envoy_config_core_v3.HeaderValue{
						rawHeaderValue(":status", statusCode),
					},
				},
			},
		},
	}
}

func responseBodyMessage(body []byte) *envoy_service_ext_proc_v3.ProcessingRequest {
	return &envoy_service_ext_proc_v3.ProcessingRequest{
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_ResponseBody{
			ResponseBody: &envoy_service_ext_proc_v3.HttpBody{
				Body:        body,
				EndOfStream: true,
			},
		},
	}
}

// assertBlockedResponse asserts that resp is an ImmediateResponse carrying
// the details blockResponse attaches: the HTTP status code, the plain-text
// body identifying the blocking rule and action, and the diagnostic headers.
func assertBlockedResponse(t *testing.T, resp *envoy_service_ext_proc_v3.ProcessingResponse, ruleID int) {
	t.Helper()

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{}, resp.GetResponse())
	immediate := resp.GetImmediateResponse()

	assert.EqualValues(t, 403, immediate.GetStatus().GetCode())
	assert.Equal(t,
		fmt.Sprintf("Request blocked by WAF - Rule ID: %d, Action: deny", ruleID),
		string(immediate.GetBody()))

	headers := map[string]string{}
	for _, opt := range immediate.GetHeaders().GetSetHeaders() {
		headers[opt.GetHeader().GetKey()] = string(opt.GetHeader().GetRawValue())
	}
	assert.Equal(t, "text/plain", headers["content-type"])
	assert.Equal(t, "1", headers["x-waf-violation"])
}

func TestProcess_CleanRequestContinues(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "blocklist"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("example.com", "/?test=clean")))
	resp, err := stream.Recv()
	require.NoError(t, err)

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestHeaders{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestBody().GetResponse().GetStatus())

	require.NoError(t, stream.CloseSend())
}

func TestProcess_MaliciousRequestIsBlocked(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "blocklist"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("example.com", "/?test=malicious")))
	resp, err := stream.Recv()
	require.NoError(t, err)

	assertBlockedResponse(t, resp, 1000)
}

// TestProcess_AgentgatewayPseudoHeaderEncodingIsBlocked is a regression test
// for a real bug: agentgateway sends pseudo-headers (:authority, :method,
// :path) using the ext_proc HeaderValue's `value` wire field, not
// `raw_value`. The processor used to read only raw_value, so every request
// looked like it was missing its pseudo-headers and silently skipped the
// WAF - a malicious request would CONTINUE instead of being blocked,
// regardless of what SecRule directives were configured. See
// handlers.go's headerValue doc comment for the fix.
func TestProcess_AgentgatewayPseudoHeaderEncodingIsBlocked(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "blocklist"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessageAgentgatewayEncoding("/?test=malicious")))
	resp, err := stream.Recv()
	require.NoError(t, err)

	assertBlockedResponse(t, resp, 1000)
}

// TestProcess_CleanRequestNotBlockedByCoreRuleSetAtDefaultParanoiaLevel is a
// regression test for a real bug: the processor never synthesized a "Host"
// header for Coraza from the :authority pseudo-header (HTTP/2's, and
// ext_proc's, stand-in for it), so Coraza's REQUEST_HEADERS never actually
// contained "Host". That made OWASP CRS's own
// REQUEST-920-PROTOCOL-ENFORCEMENT.conf rule 920280 ("Request Missing a
// Host Header") fire as a false positive on every single request -
// contributing CRS's critical_anomaly_score, which equals the default
// paranoia-level-1 inbound threshold on its own, so any request that
// reached the request-body blocking-evaluation phase (e.g. any request
// with a body) was blocked regardless of whether it was actually
// malicious. Uses the real, full Core Rule Set (like
// internal/processor/config's TestCompileWithCoreRuleSet) rather than a
// toy SecRule, since this false positive only exists in CRS's own
// protocol-enforcement rules.
func TestProcess_CleanRequestNotBlockedByCoreRuleSetAtDefaultParanoiaLevel(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"crs": "Include @coraza.conf-recommended\n" +
				"SecRuleEngine On\n" +
				"Include @crs-setup.conf.example\n" +
				"Include @owasp_crs/*.conf\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "crs"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessageAgentgatewayEncoding("/get")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestHeaders{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	// The blocking-evaluation rule this bug tripped only runs once the
	// request-body phase completes (see the doc comment above), so the
	// stream must reach that phase for this test to actually exercise it.
	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestBody{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestBody().GetResponse().GetStatus(),
		"a clean request through the full Core Rule Set at the default paranoia level must not be blocked")

	require.NoError(t, stream.CloseSend())
}

// TestProcess_BodylessQueryStringAttackBlockedByCoreRuleSet is
// TestProcess_BodylessRequestQueryStringAttackIsBlocked's real-CRS-ruleset
// counterpart: it proves the fix works against the actual OWASP Core Rule
// Set signature rules (CRS's 941xxx XSS rules in this case), not just a
// toy phase:2 SecRule, mirroring the exact live-cluster reproduction: a
// bodyless GET carrying a URL-decoded XSS payload purely in its query
// string.
func TestProcess_BodylessQueryStringAttackBlockedByCoreRuleSet(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"crs": "Include @coraza.conf-recommended\n" +
				"SecRuleEngine On\n" +
				"Include @crs-setup.conf.example\n" +
				"Include @owasp_crs/*.conf\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "crs"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	msg := requestHeadersMessageAgentgatewayEncoding("/get?q=<script>alert(1)</script>")
	msg.GetRequestHeaders().EndOfStream = true
	require.NoError(t, stream.Send(msg))
	resp, err := stream.Recv()
	require.NoError(t, err)

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{}, resp.GetResponse(),
		"a bodyless GET with an XSS payload in its query string must be blocked by the Core Rule Set")
	assert.EqualValues(t, 403, resp.GetImmediateResponse().GetStatus().GetCode())
}

// TestProcess_BodylessRequestQueryStringAttackIsBlocked is a regression
// test for a real bug: Coraza's phase:2 rules - the phase CRS's own
// ARGS-inspecting signature rules (e.g. 941xxx XSS, 942xxx SQLi) are
// declared under - only run inside tx.ProcessRequestBody(), which used to
// only ever be invoked from the request-body ext_proc phase. But per the
// ext_proc protocol contract (envoy.service.ext_proc.v3.HttpHeaders.
// end_of_stream's own doc comment), EndOfStream == true on the headers
// message means no RequestBody message will ever be sent for this stream
// at all - true for any GET/HEAD/DELETE (or any other bodyless) request.
// So any attack carried purely in the query string was never evaluated by
// phase:2 rules at all, and slipped through completely undetected -
// confirmed live against agentgateway, where a bodyless GET with a
// URL-encoded XSS/SQLi payload in its query string produced zero "WAF
// blocked traffic" log lines. See handlers.go's
// processEndOfRequestWithNoBody for the fix.
func TestProcess_BodylessRequestQueryStringAttackIsBlocked(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:2,deny,status:403"` + "\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "blocklist"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	// A bodyless GET: agentgateway (and any ext_proc-compliant client)
	// sets EndOfStream on the request-headers message itself when there
	// is no request body, and never sends a RequestBody message at all.
	msg := requestHeadersMessageAgentgatewayEncoding("/?test=malicious")
	msg.GetRequestHeaders().EndOfStream = true
	require.NoError(t, stream.Send(msg))
	resp, err := stream.Recv()
	require.NoError(t, err)

	assertBlockedResponse(t, resp, 1000)
}

// TestProcess_RequestBodyMessageAfterEndOfStreamHeadersIsHarmless covers a
// protocol-anomalous edge case that processEndOfRequestWithNoBody's fix
// introduces a theoretical risk for: what if a RequestBody message still
// arrives even though the request-headers message already had
// EndOfStream set (which per the ext_proc protocol contract should mean no
// such message is ever sent)? tx.ProcessRequestBody() would then be
// invoked a second time for the same transaction. This asserts that's
// safe - no panic, no error, no duplicate block - relying on Coraza's own
// per-transaction phase tracking (tx.lastPhase) rather than any extra
// bookkeeping in requestState; see processEndOfRequestWithNoBody's doc
// comment.
func TestProcess_RequestBodyMessageAfterEndOfStreamHeadersIsHarmless(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:2,deny,status:403"` + "\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "blocklist"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	msg := requestHeadersMessageAgentgatewayEncoding("/?test=clean")
	msg.GetRequestHeaders().EndOfStream = true
	require.NoError(t, stream.Send(msg))
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestHeaders{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	// A RequestBody message that should never arrive per the protocol
	// contract, but the server must not misbehave if it does anyway.
	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestBody{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestBody().GetResponse().GetStatus())

	require.NoError(t, stream.CloseSend())
}

func TestProcess_UnmatchedRouteContinues(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "blocklist"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	// unmatched.example.com has no route, so even a "malicious" query
	// string must be let through unprotected.
	require.NoError(t, stream.Send(requestHeadersMessage("unmatched.example.com", "/?test=malicious")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
}

// TestProcess_FullRoundTripContinues drives all four ext_proc phases (request
// headers, request body, response headers, response body) through a single
// stream for a clean request/response pair, asserting each phase responds
// with the correctly-typed CONTINUE.
func TestProcess_FullRoundTripContinues(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "blocklist"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("example.com", "/?test=clean")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestHeaders{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestBody{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestBody().GetResponse().GetStatus())

	require.NoError(t, stream.Send(responseHeadersMessage("200")))
	resp, err = stream.Recv()
	require.NoError(t, err)
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ResponseHeaders{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetResponseHeaders().GetResponse().GetStatus())

	require.NoError(t, stream.Send(responseBodyMessage([]byte("ok"))))
	resp, err = stream.Recv()
	require.NoError(t, err)
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ResponseBody{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetResponseBody().GetResponse().GetStatus())

	require.NoError(t, stream.CloseSend())
}

// TestProcess_ResponseHeadersBlocked exercises a phase:3 (response headers)
// rule matching on RESPONSE_STATUS, which Coraza populates directly from the
// status code ProcessResponseHeaders is called with - no response header
// population is required for this to work.
func TestProcess_ResponseHeadersBlocked(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule RESPONSE_STATUS "@streq 500" "id:3000,phase:3,deny,status:403,msg:'response blocked'"` + "\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "blocklist"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("example.com", "/")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestBody().GetResponse().GetStatus())

	require.NoError(t, stream.Send(responseHeadersMessage("500")))
	resp, err = stream.Recv()
	require.NoError(t, err)

	assertBlockedResponse(t, resp, 3000)
}

// TestProcess_ResponseBodyBlocked exercises a phase:4 (response body) rule.
// RESPONSE_BODY is only populated when the response Content-Type is in
// Coraza's configured mime-type allowlist, or when a rule forces it via
// ctl:forceResponseBodyVariable; the directives below use the latter so the
// test doesn't depend on response header population.
func TestProcess_ResponseBodyBlocked(t *testing.T) {
	cfg := &config.Config{
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				"SecResponseBodyAccess On\n" +
				`SecRule RESPONSE_STATUS "@ge 0" "id:3999,phase:3,pass,nolog,ctl:forceResponseBodyVariable=On"` + "\n" +
				`SecRule RESPONSE_BODY "@contains malicious" "id:4000,phase:4,deny,status:403,msg:'response body blocked'"` + "\n",
		},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "blocklist"}},
		},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("example.com", "/")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestBody().GetResponse().GetStatus())

	require.NoError(t, stream.Send(responseHeadersMessage("200")))
	resp, err = stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetResponseHeaders().GetResponse().GetStatus())

	require.NoError(t, stream.Send(responseBodyMessage([]byte("this body is malicious"))))
	resp, err = stream.Recv()
	require.NoError(t, err)

	assertBlockedResponse(t, resp, 4000)
}
