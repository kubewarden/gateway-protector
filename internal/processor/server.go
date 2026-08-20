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

// New creates a Server that starts serving with the given Snapshot (nil
// until the processor has received its first config from the controller -
// see internal/processor/config.Subscriber). Use SetSnapshot to hot-swap
// the engines/routes it uses, e.g. after a config push. A nil logger
// defaults to [slog.Default].
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
// The previous Snapshot's engines are closed once swapped out (see
// config.Snapshot.Close), releasing the entries they own in Coraza's
// process-wide memoize cache for compiled regex/aho-corasick patterns.
// This is safe to do immediately, even though in-flight requests may still
// be using the old Snapshot's engines: Coraza's WAFCloser contract
// guarantees closing a WAF only releases shared cache entries, leaving any
// transaction already created from it fully functional. Without this, a
// processor that reloads config frequently would slowly leak that cache
// (see coraza/v3's experimental.WAFCloser).
func (s *Server) SetSnapshot(snapshot *config.Snapshot) {
	old := s.snapshot.Swap(snapshot)
	if old == nil || old == snapshot {
		return
	}

	if err := old.Close(); err != nil {
		s.logger.Error("Failed to close previous Snapshot's WAF engines", slog.Any("error", err))
	}
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

	// requestBody and responseBody track each direction's body stream
	// across ext_proc messages: whether chunks are being withheld
	// pending a WAF verdict, and whether the corresponding Coraza body
	// phase has already been evaluated.
	requestBody  bodyPhaseState
	responseBody bodyPhaseState
}

// bodyPhaseState tracks one direction's body stream (see requestState).
//
// In agentgateway's FULL_DUPLEX_STREAMED mode the proxied body is rebuilt
// exclusively from the chunks this server echoes back, which is what makes
// withholding possible at all: as long as the verdict is pending, received
// chunks are simply not answered (agentgateway explicitly supports the
// server buffering headers + body before responding), and are then either
// all echoed (clean) or superseded by a single ImmediateResponse (blocked).
type bodyPhaseState struct {
	// holding is true while chunks (and, for the response direction,
	// the headers answer) are withheld pending the body-phase verdict.
	holding bool

	// heldHeadersResponse is the deferred ResponseHeaders answer
	// (response direction only): agentgateway commits the response head
	// downstream as soon as that answer is sent, so it must be
	// withheld for an ImmediateResponse at the phase-4 verdict to still
	// be able to replace the response.
	heldHeadersResponse *envoy_service_ext_proc_v3.ProcessingResponse

	// held are the withheld body messages, one entry per message, each
	// owed an echo answer once the verdict is clean.
	held []heldChunk

	// evaluated is true once the Coraza body phase for this direction
	// has run (at end-of-stream, at a body-limit ProcessPartial
	// evaluation, or synthetically for bodyless messages).
	evaluated bool
}

// heldChunk is one withheld body message.
type heldChunk struct {
	data        []byte
	endOfStream bool
}

// release ends the holding state, returning every response owed so far:
// the deferred headers answer (if any) followed by one echo per withheld
// chunk. It returns nil when nothing is owed, and is safe to call on a
// stream that was never holding.
func (bs *bodyPhaseState) release(echo func([]byte, bool) *envoy_service_ext_proc_v3.ProcessingResponse) []*envoy_service_ext_proc_v3.ProcessingResponse {
	bs.holding = false

	var out []*envoy_service_ext_proc_v3.ProcessingResponse

	if bs.heldHeadersResponse != nil {
		out = append(out, bs.heldHeadersResponse)
		bs.heldHeadersResponse = nil
	}

	for _, chunk := range bs.held {
		out = append(out, echo(chunk.data, chunk.endOfStream))
	}
	bs.held = nil

	return out
}

// discard drops any withheld state without building responses for it.
// Unlike release, no echo is owed: this is used when the transaction is
// finalized by a block or engine-error ImmediateResponse (see
// blockAndClose/failAndClose), which supersedes any response still owed
// for withheld messages and terminates the whole stream - so the withheld
// chunks (and, for the response direction, the deferred headers answer)
// can be freed immediately instead of lingering, still referenced, until
// the stream itself closes.
func (bs *bodyPhaseState) discard() {
	bs.holding = false
	bs.heldHeadersResponse = nil
	bs.held = nil
}

// closeTransaction finalizes and releases the Coraza transaction, if any,
// and discards any withheld body state (see bodyPhaseState.discard) so a
// block/fail response's superseded chunks don't outlive it. Safe to call
// multiple times and on a zero-value requestState.
func (r *requestState) closeTransaction(ctx context.Context, logger *slog.Logger) {
	r.requestBody.discard()
	r.responseBody.discard()

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
// ProcessingRequest per HTTP phase event (request headers, request body
// chunks, request trailers, response headers, response body chunks,
// response trailers) and answers each with zero or more
// ProcessingResponses: zero while a body verdict is pending (the chunks
// are withheld, see bodyPhaseState), several when a verdict releases
// everything withheld at once.
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

		for _, resp := range s.handleRequest(ctx, &state, req) {
			if err := stream.Send(resp); err != nil {
				s.logger.ErrorContext(ctx, "Failed to send ext_proc response", slog.Any("error", err))
				return fmt.Errorf("ext_proc stream send failed: %w", err)
			}
		}
	}
}

// handleRequest dispatches a single ProcessingRequest to the handler for its
// phase.
func (s *Server) handleRequest(ctx context.Context, state *requestState, req *envoy_service_ext_proc_v3.ProcessingRequest) []*envoy_service_ext_proc_v3.ProcessingResponse {
	switch r := req.GetRequest().(type) {
	case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
		return s.processRequestHeaders(ctx, state, r.RequestHeaders)
	case *envoy_service_ext_proc_v3.ProcessingRequest_RequestBody:
		return s.processRequestBody(ctx, state, r.RequestBody)
	case *envoy_service_ext_proc_v3.ProcessingRequest_RequestTrailers:
		return s.processRequestTrailers(ctx, state)
	case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseHeaders:
		return s.processResponseHeaders(ctx, state, r.ResponseHeaders)
	case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseBody:
		return s.processResponseBody(ctx, state, r.ResponseBody)
	case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseTrailers:
		return s.processResponseTrailers(ctx, state)
	default:
		s.logger.WarnContext(ctx, "Unhandled ext_proc request type", slog.String("type", req.String()))
		return singleResponse(continueRequestHeaders())
	}
}
