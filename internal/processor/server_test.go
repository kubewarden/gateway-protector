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

func headerValue(key, value string) *envoy_config_core_v3.HeaderValue {
	return &envoy_config_core_v3.HeaderValue{Key: key, RawValue: []byte(value)}
}

func requestHeadersMessage(authority, path string) *envoy_service_ext_proc_v3.ProcessingRequest {
	return &envoy_service_ext_proc_v3.ProcessingRequest{
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &envoy_service_ext_proc_v3.HttpHeaders{
				Headers: &envoy_config_core_v3.HeaderMap{
					Headers: []*envoy_config_core_v3.HeaderValue{
						headerValue(":authority", authority),
						headerValue(":method", "GET"),
						headerValue(":path", path),
						headerValue(":scheme", "https"),
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
						headerValue(":status", statusCode),
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
