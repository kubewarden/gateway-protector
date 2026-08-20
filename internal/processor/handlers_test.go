package processor

import (
	"context"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/gateway-protector/internal/processor/config"
)

// newTestServer compiles cfg and wraps it in a Server, without going through
// a gRPC/bufconn round trip - used by tests that call the unexported phase
// handlers directly.
func newTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()

	require.NoError(t, config.Validate(cfg))
	snapshot, err := config.Compile(cfg, nil)
	require.NoError(t, err)

	return New(snapshot, nil)
}

// httpHeaders builds an *envoy_service_ext_proc_v3.HttpHeaders from
// key/value pairs, e.g. httpHeaders(kv{":authority", "example.com"}).
type kv struct{ key, value string }

func httpHeaders(pairs ...kv) *envoy_service_ext_proc_v3.HttpHeaders {
	headers := make([]*envoy_config_core_v3.HeaderValue, 0, len(pairs))
	for _, p := range pairs {
		headers = append(headers, rawHeaderValue(p.key, p.value))
	}
	return &envoy_service_ext_proc_v3.HttpHeaders{
		Headers: &envoy_config_core_v3.HeaderMap{Headers: headers},
	}
}

const noopDirectives = "SecRuleEngine Off\n"

func TestProcessRequestHeaders_NilHeaders(t *testing.T) {
	s := newTestServer(t, &config.Config{Directives: map[string]string{"noop": noopDirectives}})
	var state requestState

	resps := s.processRequestHeaders(context.Background(), &state, nil)

	resp := requireSingleResponse(t, resps)
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestHeaders{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
	assert.Nil(t, state.tx)
}

func TestProcessRequestHeaders_EmptyHeaderMap(t *testing.T) {
	s := newTestServer(t, &config.Config{Directives: map[string]string{"noop": noopDirectives}})
	var state requestState

	resp := requireSingleResponse(t, s.processRequestHeaders(context.Background(), &state, &envoy_service_ext_proc_v3.HttpHeaders{}))

	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
	assert.Nil(t, state.tx)
}

func TestProcessRequestHeaders_MissingPseudoHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers *envoy_service_ext_proc_v3.HttpHeaders
	}{
		{
			name:    "missing authority",
			headers: httpHeaders(kv{":method", "GET"}, kv{":path", "/"}),
		},
		{
			name:    "missing method",
			headers: httpHeaders(kv{":authority", "example.com"}, kv{":path", "/"}),
		},
		{
			name:    "missing path",
			headers: httpHeaders(kv{":authority", "example.com"}, kv{":method", "GET"}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, &config.Config{Directives: map[string]string{"noop": noopDirectives}})
			var state requestState

			resp := requireSingleResponse(t, s.processRequestHeaders(context.Background(), &state, tt.headers))

			assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
			assert.Nil(t, state.tx)
		})
	}
}

func TestProcessRequestHeaders_NoSnapshotLoadedContinues(t *testing.T) {
	s := New(nil, nil)
	var state requestState

	resp := requireSingleResponse(t, s.processRequestHeaders(context.Background(), &state,
		httpHeaders(kv{":authority", "example.com"}, kv{":method", "GET"}, kv{":path", "/"})))

	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
	assert.Nil(t, state.tx)
}

func TestProcessRequestHeaders_RouteWithoutWAFEngineContinues(t *testing.T) {
	s := newTestServer(t, &config.Config{
		Directives: map[string]string{"noop": noopDirectives},
		Routes: []config.Route{
			// No WAF ref: matched but has no engine attached (e.g. a future
			// DLP-only route).
			{Host: "dlp-only.example.com", PathPrefix: "/"},
		},
	})
	var state requestState

	resp := requireSingleResponse(t, s.processRequestHeaders(context.Background(), &state,
		httpHeaders(kv{":authority", "dlp-only.example.com"}, kv{":method", "GET"}, kv{":path", "/"})))

	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
	assert.Nil(t, state.tx)
}

func TestProcessResponseHeaders_NoTransactionContinues(t *testing.T) {
	s := newTestServer(t, &config.Config{Directives: map[string]string{"noop": noopDirectives}})
	var state requestState // state.tx is nil: no engine was attached at the headers phase.

	resp := requireSingleResponse(t, s.processResponseHeaders(context.Background(), &state, httpHeaders(kv{":status", "200"})))

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ResponseHeaders{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetResponseHeaders().GetResponse().GetStatus())
}

func TestProcessResponseBody_NoTransactionContinues(t *testing.T) {
	s := newTestServer(t, &config.Config{Directives: map[string]string{"noop": noopDirectives}})
	var state requestState // state.tx is nil: no engine was attached at the headers phase.

	resp := requireSingleResponse(t, s.processResponseBody(context.Background(), &state, &envoy_service_ext_proc_v3.HttpBody{EndOfStream: true}))

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ResponseBody{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetResponseBody().GetResponse().GetStatus())
}

// requireSingleResponse asserts a handler answered with exactly one
// response and returns it.
func requireSingleResponse(t *testing.T, resps []*envoy_service_ext_proc_v3.ProcessingResponse) *envoy_service_ext_proc_v3.ProcessingResponse {
	t.Helper()
	require.Len(t, resps, 1)

	return resps[0]
}

// TestHandleRequest_TrailersAreAcknowledged covers the trailers branches:
// agentgateway force-enables trailer delivery whenever a body mode is
// FULL_DUPLEX_STREAMED, and expects a matching TrailersResponse back (a
// mismatched message type is silently ignored on its side).
func TestHandleRequest_TrailersAreAcknowledged(t *testing.T) {
	s := newTestServer(t, &config.Config{Directives: map[string]string{"noop": noopDirectives}})
	var state requestState

	req := &envoy_service_ext_proc_v3.ProcessingRequest{
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_RequestTrailers{
			RequestTrailers: &envoy_service_ext_proc_v3.HttpTrailers{},
		},
	}

	resp := requireSingleResponse(t, s.handleRequest(context.Background(), &state, req))
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestTrailers{}, resp.GetResponse())

	req = &envoy_service_ext_proc_v3.ProcessingRequest{
		Request: &envoy_service_ext_proc_v3.ProcessingRequest_ResponseTrailers{
			ResponseTrailers: &envoy_service_ext_proc_v3.HttpTrailers{},
		},
	}

	resp = requireSingleResponse(t, s.handleRequest(context.Background(), &state, req))
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ResponseTrailers{}, resp.GetResponse())
}
