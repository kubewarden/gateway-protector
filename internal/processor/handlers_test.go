package processor

import (
	"context"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

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
	s := newTestServer(t, &config.Config{SchemaVersion: config.SchemaVersion, Directives: map[string]string{"noop": noopDirectives}})
	var state requestState

	resps := s.processRequestHeaders(context.Background(), &state, nil, nil)

	resp := requireSingleResponse(t, resps)
	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestHeaders{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
	assert.Nil(t, state.tx)
}

func TestProcessRequestHeaders_EmptyHeaderMap(t *testing.T) {
	s := newTestServer(t, &config.Config{SchemaVersion: config.SchemaVersion, Directives: map[string]string{"noop": noopDirectives}})
	var state requestState

	resp := requireSingleResponse(t, s.processRequestHeaders(context.Background(), &state, &envoy_service_ext_proc_v3.HttpHeaders{}, nil))

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
			s := newTestServer(t, &config.Config{SchemaVersion: config.SchemaVersion, Directives: map[string]string{"noop": noopDirectives}})
			var state requestState

			resp := requireSingleResponse(t, s.processRequestHeaders(context.Background(), &state, tt.headers, identityMetadata(testIdentity)))

			assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
			assert.Nil(t, state.tx)
		})
	}
}

func TestProcessRequestHeaders_NoSnapshotLoadedContinues(t *testing.T) {
	s := New(nil, nil)
	var state requestState

	resp := requireSingleResponse(t, s.processRequestHeaders(context.Background(), &state,
		httpHeaders(kv{":authority", "example.com"}, kv{":method", "GET"}, kv{":path", "/"}), identityMetadata(testIdentity)))

	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
	assert.Nil(t, state.tx)
}

func TestProcessRequestHeaders_BindingWithoutWAFEngineContinues(t *testing.T) {
	s := newTestServer(t, &config.Config{
		SchemaVersion: config.SchemaVersion,
		Directives:    map[string]string{"noop": noopDirectives},
		Bindings: []config.Binding{
			// No WAF ref: the binding matches but has no engine attached
			// (its policy failed to compile).
			{Kind: config.KindGateway, Namespace: testIdentity.GatewayNamespace, Name: testIdentity.GatewayName},
		},
	})
	var state requestState

	resp := requireSingleResponse(t, s.processRequestHeaders(context.Background(), &state,
		httpHeaders(kv{":authority", "example.com"}, kv{":method", "GET"}, kv{":path", "/"}), identityMetadata(testIdentity)))

	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())
	assert.Nil(t, state.tx)
	assert.Equal(t, testIdentity, state.identity)
}

// TestProcessRequestHeaders_InvalidIdentityFailsClosed pins that a request
// without a usable identity is answered with a 500 ImmediateResponse, not
// let through: the processor cannot tell which policy applies to it.
func TestProcessRequestHeaders_InvalidIdentityFailsClosed(t *testing.T) {
	withField := func(key string, value *structpb.Value) *envoy_config_core_v3.Metadata {
		metadata := identityMetadata(testIdentity)
		fields := metadata.GetFilterMetadata()[config.MetadataNamespace].GetFields()
		if value == nil {
			delete(fields, key)
		} else {
			fields[key] = value
		}

		return metadata
	}

	tests := []struct {
		name     string
		metadata *envoy_config_core_v3.Metadata
	}{
		{name: "no metadata at all", metadata: nil},
		{
			name: "metadata of another namespace only",
			metadata: &envoy_config_core_v3.Metadata{FilterMetadata: map[string]*structpb.Struct{
				"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{"path": structpb.NewStringValue("/")}},
			}},
		},
		{name: "missing key", metadata: withField(config.MetadataKeyRouteRule, nil)},
		{name: "key that is not a string", metadata: withField(config.MetadataKeyRouteName, structpb.NewNumberValue(1))},
		{name: "empty gateway name", metadata: withField(config.MetadataKeyGatewayName, structpb.NewStringValue(""))},
		{name: "empty route namespace", metadata: withField(config.MetadataKeyRouteNamespace, structpb.NewStringValue(""))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t, &config.Config{
				SchemaVersion: config.SchemaVersion,
				Directives:    map[string]string{"noop": noopDirectives},
				Bindings:      []config.Binding{testBinding("noop")},
			})
			var state requestState

			resp := requireSingleResponse(t, s.processRequestHeaders(context.Background(), &state,
				httpHeaders(kv{":authority", "example.com"}, kv{":method", "GET"}, kv{":path", "/"}), tt.metadata))

			require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{}, resp.GetResponse())
			assert.EqualValues(t, 500, resp.GetImmediateResponse().GetStatus().GetCode())
			assert.Nil(t, state.tx)
		})
	}
}

func TestIdentityFromMetadata(t *testing.T) {
	t.Run("reads every key", func(t *testing.T) {
		identity := config.Identity{
			GatewayNamespace: "infra",
			GatewayName:      "shared-gw",
			ListenerName:     "https",
			RouteKind:        config.KindHTTPRoute,
			RouteNamespace:   "team-shop",
			RouteName:        "shop",
			RouteRule:        "health",
		}

		got, err := identityFromMetadata(identityMetadata(identity))
		require.NoError(t, err)
		assert.Equal(t, identity, got)
	})

	t.Run("accepts an empty listener, route kind, and rule", func(t *testing.T) {
		identity := config.Identity{
			GatewayNamespace: "infra",
			GatewayName:      "shared-gw",
			RouteNamespace:   "team-shop",
			RouteName:        "shop",
		}

		got, err := identityFromMetadata(identityMetadata(identity))
		require.NoError(t, err)
		assert.Equal(t, identity, got)
	})
}

func TestProcessResponseHeaders_NoTransactionContinues(t *testing.T) {
	s := newTestServer(t, &config.Config{SchemaVersion: config.SchemaVersion, Directives: map[string]string{"noop": noopDirectives}})
	var state requestState // state.tx is nil: no engine was attached at the headers phase.

	resp := requireSingleResponse(t, s.processResponseHeaders(context.Background(), &state, httpHeaders(kv{":status", "200"})))

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ResponseHeaders{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetResponseHeaders().GetResponse().GetStatus())
}

func TestProcessResponseBody_NoTransactionContinues(t *testing.T) {
	s := newTestServer(t, &config.Config{SchemaVersion: config.SchemaVersion, Directives: map[string]string{"noop": noopDirectives}})
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
	s := newTestServer(t, &config.Config{SchemaVersion: config.SchemaVersion, Directives: map[string]string{"noop": noopDirectives}})
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
