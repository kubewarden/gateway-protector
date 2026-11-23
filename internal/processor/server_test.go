package processor

import (
	"context"
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
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/kubewarden/gateway-protector/internal/processor/config"
)

const bufSize = 1024 * 1024

// startTestServer starts the processor's Server over an in-memory bufconn
// listener with the given config, returning a connected ext_proc client and
// a cleanup function.
func startTestServer(t *testing.T, cfg *config.Config) envoy_service_ext_proc_v3.ExternalProcessorClient {
	t.Helper()

	client, _ := startTestServerWithHandle(t, cfg)

	return client
}

// startTestServerWithHandle is startTestServer, but also returns the
// underlying *Server so tests can drive it directly (e.g. call
// SetSnapshot) alongside an active ext_proc stream.
func startTestServerWithHandle(t *testing.T, cfg *config.Config) (envoy_service_ext_proc_v3.ExternalProcessorClient, *Server) {
	t.Helper()

	require.NoError(t, config.Validate(cfg))
	snapshot, err := config.Compile(cfg, nil)
	require.NoError(t, err)

	server := New(snapshot, nil)

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(grpcServer, server)

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

	return envoy_service_ext_proc_v3.NewExternalProcessorClient(conn), server
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

// testIdentity is the identity that requestHeadersMessage and
// requestHeadersMessageAgentgatewayEncoding send: a request that the
// "infra/gw" Gateway accepted on its "http" listener and sent to the unnamed
// rule of the "app/web" HTTPRoute. testBinding binds that Gateway.
var testIdentity = config.Identity{
	GatewayNamespace: "infra",
	GatewayName:      "gw",
	ListenerName:     "http",
	RouteKind:        config.KindHTTPRoute,
	RouteNamespace:   "app",
	RouteName:        "web",
}

// testBinding binds the Gateway of testIdentity to engineKey.
func testBinding(engineKey string) config.Binding {
	return config.Binding{
		Kind:      config.KindGateway,
		Namespace: testIdentity.GatewayNamespace,
		Name:      testIdentity.GatewayName,
		WAF:       &config.WAFRef{EngineKey: engineKey},
	}
}

// identityMetadata builds the ext_proc metadata that agentgateway sends
// for a request with the given identity, as the generated
// AgentgatewayPolicy asks it to (see identityFromMetadata).
func identityMetadata(id config.Identity) *envoy_config_core_v3.Metadata {
	return &envoy_config_core_v3.Metadata{
		FilterMetadata: map[string]*structpb.Struct{
			config.MetadataNamespace: {Fields: map[string]*structpb.Value{
				config.MetadataKeyGatewayNamespace: structpb.NewStringValue(id.GatewayNamespace),
				config.MetadataKeyGatewayName:      structpb.NewStringValue(id.GatewayName),
				config.MetadataKeyListenerName:     structpb.NewStringValue(id.ListenerName),
				config.MetadataKeyRouteKind:        structpb.NewStringValue(id.RouteKind),
				config.MetadataKeyRouteNamespace:   structpb.NewStringValue(id.RouteNamespace),
				config.MetadataKeyRouteName:        structpb.NewStringValue(id.RouteName),
				config.MetadataKeyRouteRule:        structpb.NewStringValue(id.RouteRule),
			}},
		},
	}
}

// requestHeadersMessage builds the request headers message of a GET request
// for path on example.com, with testIdentity.
func requestHeadersMessage(path string) *envoy_service_ext_proc_v3.ProcessingRequest {
	return requestHeadersMessageWithIdentity(path, testIdentity)
}

func requestHeadersMessageWithIdentity(path string, id config.Identity) *envoy_service_ext_proc_v3.ProcessingRequest {
	return &envoy_service_ext_proc_v3.ProcessingRequest{
		MetadataContext: identityMetadata(id),
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &envoy_service_ext_proc_v3.HttpHeaders{
				Headers: &envoy_config_core_v3.HeaderMap{
					Headers: []*envoy_config_core_v3.HeaderValue{
						rawHeaderValue(":authority", "example.com"),
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
// authority is always "example.com" and the identity is always
// testIdentity here (every test config below binds that identity to a WAF
// engine), so they're hardcoded rather than taken as parameters.
func requestHeadersMessageAgentgatewayEncoding(path string) *envoy_service_ext_proc_v3.ProcessingRequest {
	return &envoy_service_ext_proc_v3.ProcessingRequest{
		MetadataContext: identityMetadata(testIdentity),
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

func responseHeadersMessage(statusCode string, extraHeaders ...*envoy_config_core_v3.HeaderValue) *envoy_service_ext_proc_v3.ProcessingRequest {
	headers := append(
		[]*envoy_config_core_v3.HeaderValue{rawHeaderValue(":status", statusCode)},
		extraHeaders...)

	return &envoy_service_ext_proc_v3.ProcessingRequest{
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &envoy_service_ext_proc_v3.HttpHeaders{
				Headers: &envoy_config_core_v3.HeaderMap{
					Headers: headers,
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
// the details blockResponse attaches: the HTTP status code, an empty body
// (rule details are deliberately not disclosed to the client - see
// blockResponse), and the x-waf-violation marker header.
func assertBlockedResponse(t *testing.T, resp *envoy_service_ext_proc_v3.ProcessingResponse, ruleID int) {
	t.Helper()

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{}, resp.GetResponse())
	immediate := resp.GetImmediateResponse()

	assert.EqualValues(t, 403, immediate.GetStatus().GetCode())
	assert.Empty(t, immediate.GetBody(),
		"block response must not disclose rule details (rule %d) to the client", ruleID)

	headers := map[string]string{}
	for _, opt := range immediate.GetHeaders().GetSetHeaders() {
		headers[opt.GetHeader().GetKey()] = string(opt.GetHeader().GetRawValue())
	}
	assert.Equal(t, "1", headers["x-waf-violation"])
}

func TestProcess_CleanRequestContinues(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("/?test=clean")))
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
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("/?test=malicious")))
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
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
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
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"crs": "Include @coraza.conf-recommended\n" +
				"SecRuleEngine On\n" +
				"Include @crs-setup.conf.example\n" +
				"Include @owasp_crs/*.conf\n",
		},
		Bindings: []config.Binding{testBinding("crs")},
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
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"crs": "Include @coraza.conf-recommended\n" +
				"SecRuleEngine On\n" +
				"Include @crs-setup.conf.example\n" +
				"Include @owasp_crs/*.conf\n",
		},
		Bindings: []config.Binding{testBinding("crs")},
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
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:2,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
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
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:2,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
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

func TestProcess_UnboundIdentityContinues(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	// No binding covers the other-gw Gateway, so even a "malicious" query
	// string must be let through unprotected.
	unbound := testIdentity
	unbound.GatewayName = "other-gw"
	require.NoError(t, stream.Send(requestHeadersMessageWithIdentity("/?test=malicious", unbound)))
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
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("/?test=clean")))
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
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule RESPONSE_STATUS "@streq 500" "id:3000,phase:3,deny,status:403,msg:'response blocked'"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("/")))
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

// TestProcess_ResponseHeaderValueBlocked exercises a phase:3 rule matching
// on an actual RESPONSE_HEADERS value, which requires the response-headers
// phase to feed every header into the transaction (not just :status).
// Regression test for the gap caught by Coraza's connector e2e suite (see
// test/coraza-e2e): response headers used to never be added to the
// transaction at all, so rules like this one (or CRS's 95x leakage rules)
// could never fire.
func TestProcess_ResponseHeaderValueBlocked(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule RESPONSE_HEADERS:pass "@rx leak" "id:3100,phase:3,t:lowercase,deny,status:403,msg:'response header blocked'"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("/")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestBody().GetResponse().GetStatus())

	require.NoError(t, stream.Send(responseHeadersMessage("200", rawHeaderValue("pass", "leak"))))
	resp, err = stream.Recv()
	require.NoError(t, err)

	assertBlockedResponse(t, resp, 3100)
}

// TestProcess_ResponseBodyBlockedViaMimeType exercises the standard (non
// ctl-forced) way response bodies become inspectable: Coraza only
// populates RESPONSE_BODY when the response's Content-Type is in the
// SecResponseBodyMimeType allowlist, and it learns that Content-Type from
// the response-headers phase. Regression test for the same gap as
// TestProcess_ResponseHeaderValueBlocked: with response headers never fed
// to the transaction, the mime-type gate never opened and phase-4 rules
// silently never ran on real traffic.
func TestProcess_ResponseBodyBlockedViaMimeType(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				"SecResponseBodyAccess On\n" +
				"SecResponseBodyMimeType application/json\n" +
				`SecRule RESPONSE_BODY "@contains malicious" "id:4100,phase:4,deny,status:403,msg:'response body blocked'"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("/")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestBody().GetResponse().GetStatus())

	// The response body will be inspected (Content-Type is in the
	// SecResponseBodyMimeType allowlist), so the ResponseHeaders answer
	// is withheld until the phase-4 verdict: no response is owed yet.
	require.NoError(t, stream.Send(responseHeadersMessage("200", rawHeaderValue("content-type", "application/json"))))

	require.NoError(t, stream.Send(responseBodyMessage([]byte(`{"data":"malicious"}`))))
	resp, err = stream.Recv()
	require.NoError(t, err)

	assertBlockedResponse(t, resp, 4100)
}

// TestProcess_CleanInspectableResponseBodyIsReleased is the clean-path
// counterpart of TestProcess_ResponseBodyBlockedViaMimeType: while the
// phase-4 verdict is pending, the ResponseHeaders answer and the body
// chunks are withheld (agentgateway commits the response head downstream
// as soon as the headers answer is sent, so answering early would make a
// later block impossible); once the verdict is clean, everything owed is
// released at once - the headers CONTINUE followed by one echo per body
// message, carrying the original bytes in streamed_response.
func TestProcess_CleanInspectableResponseBodyIsReleased(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				"SecResponseBodyAccess On\n" +
				"SecResponseBodyMimeType application/json\n" +
				`SecRule RESPONSE_BODY "@contains malicious" "id:4200,phase:4,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("/")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	// Headers answer withheld: nothing to receive until the verdict.
	require.NoError(t, stream.Send(responseHeadersMessage("200", rawHeaderValue("content-type", "application/json"))))

	body := []byte(`{"data":"clean"}`)
	require.NoError(t, stream.Send(responseBodyMessage(body)))

	// Clean verdict: the deferred ResponseHeaders CONTINUE arrives
	// first...
	resp, err = stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetResponseHeaders().GetResponse().GetStatus())

	// ...followed by the echo of the withheld body chunk.
	resp, err = stream.Recv()
	require.NoError(t, err)
	streamed := resp.GetResponseBody().GetResponse().GetBodyMutation().GetStreamedResponse()
	require.NotNil(t, streamed, "body chunk must be echoed via streamed_response")
	assert.Equal(t, body, streamed.GetBody())
	assert.True(t, streamed.GetEndOfStream())
}

// TestProcess_ResponseBodyBlocked exercises a phase:4 (response body) rule.
// RESPONSE_BODY is only populated when the response Content-Type is in
// Coraza's configured mime-type allowlist, or when a rule forces it via
// ctl:forceResponseBodyVariable; the directives below use the latter so the
// test doesn't depend on response header population.
func TestProcess_ResponseBodyBlocked(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				"SecResponseBodyAccess On\n" +
				`SecRule RESPONSE_STATUS "@ge 0" "id:3999,phase:3,pass,nolog,ctl:forceResponseBodyVariable=On"` + "\n" +
				`SecRule RESPONSE_BODY "@contains malicious" "id:4000,phase:4,deny,status:403,msg:'response body blocked'"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
	}
	client := startTestServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("/")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestBody().GetResponse().GetStatus())

	// ctl:forceResponseBodyVariable makes the body inspectable, so the
	// ResponseHeaders answer is withheld until the phase-4 verdict.
	require.NoError(t, stream.Send(responseHeadersMessage("200")))

	require.NoError(t, stream.Send(responseBodyMessage([]byte("this body is malicious"))))
	resp, err = stream.Recv()
	require.NoError(t, err)

	assertBlockedResponse(t, resp, 4000)
}

// TestServer_SetSnapshot_SwapsActiveSnapshot asserts that a request started
// after SetSnapshot uses the newly set Snapshot's engine (and bindings), not
// the one the Server was created with.
func TestServer_SetSnapshot_SwapsActiveSnapshot(t *testing.T) {
	oldCfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"old": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:1,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("old")},
	}
	client, server := startTestServerWithHandle(t, oldCfg)

	newCfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"new": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq new-malicious" "id:2000,phase:1,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("new")},
	}
	require.NoError(t, config.Validate(newCfg))
	newSnapshot, err := config.Compile(newCfg, nil)
	require.NoError(t, err)

	server.SetSnapshot(newSnapshot)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	// The old engine's rule (id:1000) must no longer trigger...
	require.NoError(t, stream.Send(requestHeadersMessage("/?test=malicious")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestBody().GetResponse().GetStatus())
	require.NoError(t, stream.CloseSend())

	// ...while the new engine's rule (id:2000) does.
	stream2, err := client.Process(ctx)
	require.NoError(t, err)
	require.NoError(t, stream2.Send(requestHeadersMessage("/?test=new-malicious")))
	resp, err = stream2.Recv()
	require.NoError(t, err)
	assertBlockedResponse(t, resp, 2000)
}

// TestServer_SetSnapshot_InFlightRequestSurvivesPreviousSnapshotClose is a
// regression test for the fix documented on Server.SetSnapshot: closing the
// previous Snapshot's WAF engines (to release their entries in Coraza's
// process-wide memoize cache - see config.Snapshot.Close) must not break a
// request that is still in flight against that old Snapshot. It starts a
// stream against the initial Snapshot, swaps in a brand-new one mid-stream
// (closing the first), then drives the rest of the original stream to
// completion and asserts it still blocks correctly.
func TestServer_SetSnapshot_InFlightRequestSurvivesPreviousSnapshotClose(t *testing.T) {
	cfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives: map[string]string{
			"blocklist": "SecRuleEngine On\n" +
				`SecRule ARGS:test "@streq malicious" "id:1000,phase:2,deny,status:403"` + "\n",
		},
		Bindings: []config.Binding{testBinding("blocklist")},
	}
	client, server := startTestServerWithHandle(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	// Start the request against the Server's initial Snapshot; this
	// creates a Coraza transaction bound to its "blocklist" engine.
	require.NoError(t, stream.Send(requestHeadersMessage("/?test=malicious")))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	// Swap in an unrelated Snapshot while the above stream is still open:
	// this closes the original Snapshot's "blocklist" engine (the one the
	// in-flight stream's transaction was created from).
	otherCfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives:    map[string]string{"noop": "SecRuleEngine On\n"},
		Bindings: []config.Binding{
			{Kind: config.KindGateway, Namespace: "infra", Name: "other-gw", WAF: &config.WAFRef{EngineKey: "noop"}},
		},
	}
	require.NoError(t, config.Validate(otherCfg))
	otherSnapshot, err := config.Compile(otherCfg, nil)
	require.NoError(t, err)
	server.SetSnapshot(otherSnapshot)

	// The original stream's phase:2 rule must still fire correctly even
	// though its engine was closed out from under it.
	require.NoError(t, stream.Send(requestBodyMessage()))
	resp, err = stream.Recv()
	require.NoError(t, err)

	assertBlockedResponse(t, resp, 1000)
}

// TestServer_SetSnapshot_NilAndRepeatedCallsAreSafe covers the guard in
// SetSnapshot against closing a nil previous Snapshot (the Server's initial
// state before any config is received) and against closing a Snapshot that
// is being set again as itself (a no-op config push should never close the
// engines still actively serving requests).
func TestServer_SetSnapshot_NilAndRepeatedCallsAreSafe(t *testing.T) {
	server := New(nil, nil)

	cfg := &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives:    map[string]string{"noop": "SecRuleEngine On\n"},
		Bindings:      []config.Binding{testBinding("noop")},
	}
	require.NoError(t, config.Validate(cfg))
	snapshot, err := config.Compile(cfg, nil)
	require.NoError(t, err)

	// First call: the previous Snapshot is nil, so there is nothing to
	// close.
	assert.NotPanics(t, func() { server.SetSnapshot(snapshot) })

	// Setting the exact same Snapshot pointer again must not close the
	// engines it holds - they may still be in active use.
	assert.NotPanics(t, func() { server.SetSnapshot(snapshot) })
}
