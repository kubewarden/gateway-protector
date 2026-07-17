// Package processor implements the Envoy ext_proc gRPC service that runs the
// WAF engine (and, in the future, DLP) for Gateway Protector: agentgateway
// calls this service once per HTTP request/response, over a single
// bidirectional gRPC stream that spans all four processing phases (request
// headers, request body, response headers, response body), so one process
// can run WAF (request-phase allow/block) and DLP (response-phase
// redact/mask/block, not yet implemented) with a single network hop instead
// of two. See docs/processor.md for the full request-time flow and
// configuration schema.
package processor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	coraza_types "github.com/corazawaf/coraza/v3/types"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/kubewarden/gateway-protector/internal/processor/config"
)

// Server implements the Envoy ext_proc ExternalProcessorServer, running the
// WAF engine selected by the request's host+path. Engine selection lives
// entirely in this data-plane process: the processor holds a host+path ->
// engine routing table built from its own config file (see
// internal/processor/config.Snapshot.Match), rather than encoding a host
// inventory in the gateway's per-request expression language, which would
// need to grow unboundedly as more apps/policies are added.
//
// Server keeps no cross-stream state: an Envoy ext_proc gRPC stream corresponds
// to a single HTTP request/response, so all per-request state (the Coraza transaction, matched route, etc.)
// lives in a local requestState value scoped to that Process() call.
type Server struct {
	envoy_service_ext_proc_v3.UnimplementedExternalProcessorServer

	snapshot atomic.Pointer[config.Snapshot]
	logger   *slog.Logger
}

// New creates a Server that starts serving with the given Snapshot. Use
// SetSnapshot to hot-swap the engines/routes it uses, e.g. after a config
// reload (see internal/processor/config.Watcher). A nil logger defaults to
// [slog.Default].
func New(initial *config.Snapshot, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{logger: logger}
	s.snapshot.Store(initial)
	return s
}

// SetSnapshot atomically replaces the Snapshot used by subsequent requests.
// In-flight requests keep using the Snapshot (and thus the coraza.WAF
// engine) that was active when they started.
//
// TODO: Coraza memoizes compiled regex/aho-corasick patterns in a process-wide
// cache by default; discarding the old Snapshot's engines here does not
// release those entries (see coraza/v3's experimental.WAFCloser and its
// README's "coraza.rule.multiphase_evaluation"/memoization notes). On a
// processor that reloads config frequently this is a slow memory leak -
// revisit by calling WAFCloser.Close() on the previous snapshot's engines
// once they are no longer in use by any in-flight request.
func (s *Server) SetSnapshot(snapshot *config.Snapshot) {
	s.snapshot.Store(snapshot)
}

// requestState holds the per-request state for a single ext_proc stream.
type requestState struct {
	// tx is the Coraza transaction for this request, created once the
	// request headers phase resolves a WAF engine for the request. It
	// stays nil for requests that don't match any route with a WAF
	// engine attached.
	tx coraza_types.Transaction

	// authority and path are recorded at the request-headers phase for
	// logging in later phases (e.g. the block response).
	authority string
	path      string
}

// closeTransaction finalizes and releases the Coraza transaction, if any.
// Safe to call multiple times and on a zero-value requestState.
func (r *requestState) closeTransaction(ctx context.Context, logger *slog.Logger) {
	if r.tx == nil {
		return
	}
	r.tx.ProcessLogging()
	if err := r.tx.Close(); err != nil {
		logger.ErrorContext(ctx, "Failed to close Coraza transaction", slog.Any("error", err))
	}
	r.tx = nil
}

// Process implements the main ext_proc bidirectional stream: it receives one
// ProcessingRequest per HTTP phase (request headers, request body, response
// headers, response body) and must send back exactly one ProcessingResponse
// for each, in order (see the envoy.service.ext_proc.v3 proto docs embedded
// in external_processor.pb.go).
func (s *Server) Process(stream envoy_service_ext_proc_v3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	var state requestState
	defer state.closeTransaction(ctx, s.logger)

	for {
		req, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			s.logger.DebugContext(ctx, "ext_proc stream ended", slog.Any("error", err))
			return fmt.Errorf("ext_proc stream receive failed: %w", err)
		}

		resp := s.handleRequest(ctx, &state, req)

		if err := stream.Send(resp); err != nil {
			s.logger.ErrorContext(ctx, "Failed to send ext_proc response", slog.Any("error", err))
			return fmt.Errorf("ext_proc stream send failed: %w", err)
		}
	}
}

// handleRequest dispatches a single ProcessingRequest to the handler for its
// phase.
func (s *Server) handleRequest(ctx context.Context, state *requestState, req *envoy_service_ext_proc_v3.ProcessingRequest) *envoy_service_ext_proc_v3.ProcessingResponse {
	switch r := req.GetRequest().(type) {
	case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
		return s.processRequestHeaders(ctx, state, r.RequestHeaders)
	case *envoy_service_ext_proc_v3.ProcessingRequest_RequestBody:
		return s.processRequestBody(ctx, state, r.RequestBody)
	case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseHeaders:
		return s.processResponseHeaders(ctx, state, r.ResponseHeaders)
	case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseBody:
		return s.processResponseBody(ctx, state, r.ResponseBody)
	default:
		s.logger.WarnContext(ctx, "Unhandled ext_proc request type", slog.String("type", req.String()))
		return continueRequestHeaders()
	}
}
