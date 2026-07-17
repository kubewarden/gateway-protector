package processor

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	coraza_types "github.com/corazawaf/coraza/v3/types"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// httpProtocol is used when calling into Coraza's Process{Request,Response}
// phases; ext_proc does not expose the HTTP protocol version anywhere
// meaningful for our purposes, so a constant value is used consistently for
// both phases of a given transaction. Coraza only uses it for informational
// SecLang variables (e.g. REQUEST_PROTOCOL).
const httpProtocol = "HTTP/1.1"

// processRequestHeaders handles the request-headers phase: it resolves the
// WAF engine for this request's host+path (the host+path routing table
// selects the engine, see internal/processor/config.Snapshot.Match) and, if
// one is attached, starts a Coraza transaction and evaluates phase 1/2
// rules.
func (s *Server) processRequestHeaders(ctx context.Context, state *requestState, headers *envoy_service_ext_proc_v3.HttpHeaders) *envoy_service_ext_proc_v3.ProcessingResponse {
	if headers == nil || headers.GetHeaders() == nil {
		s.logger.WarnContext(ctx, "ext_proc sent request headers phase with no headers")
		return continueRequestHeaders()
	}

	var authority, method, path string
	for _, header := range headers.GetHeaders().GetHeaders() {
		if header == nil {
			continue
		}
		switch strings.ToLower(header.GetKey()) {
		case ":authority", "host":
			authority = string(header.GetRawValue())
		case ":method":
			method = string(header.GetRawValue())
		case ":path":
			path = string(header.GetRawValue())
		}
	}

	if authority == "" || method == "" || path == "" {
		s.logger.WarnContext(ctx, "ext_proc request headers missing pseudo-headers, skipping WAF",
			slog.String("authority", authority), slog.String("method", method), slog.String("path", path))
		return continueRequestHeaders()
	}

	state.authority = authority
	state.path = path

	snapshot := s.snapshot.Load()
	if snapshot == nil {
		s.logger.ErrorContext(ctx, "Processor has no config loaded, skipping WAF", slog.String("authority", authority))
		return continueRequestHeaders()
	}

	waf, matched := snapshot.Match(authority, path)
	if !matched {
		s.logger.DebugContext(ctx, "No route matched, request is unprotected", slog.String("authority", authority), slog.String("path", path))
		return continueRequestHeaders()
	}
	if waf == nil {
		// Route matched but has no WAF engine attached (e.g. a future
		// DLP-only route).
		return continueRequestHeaders()
	}

	tx := waf.NewTransaction()
	state.tx = tx

	tx.ProcessURI(path, method, httpProtocol)
	for _, header := range headers.GetHeaders().GetHeaders() {
		if header == nil || strings.HasPrefix(header.GetKey(), ":") {
			continue
		}
		tx.AddRequestHeader(header.GetKey(), string(header.GetRawValue()))
	}

	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return s.blockAndClose(ctx, state, interruption)
	}

	return continueRequestHeaders()
}

// processRequestBody handles the request-body phase, feeding body chunks
// into the transaction started (if any) during the headers phase.
func (s *Server) processRequestBody(ctx context.Context, state *requestState, body *envoy_service_ext_proc_v3.HttpBody) *envoy_service_ext_proc_v3.ProcessingResponse {
	if state.tx == nil {
		return continueRequestBody()
	}

	return s.processBody(ctx, state, body, continueRequestBody,
		state.tx.WriteRequestBody, state.tx.ProcessRequestBody,
		"Failed to write request body to WAF transaction", "Failed to process request body")
}

// processResponseHeaders handles the response-headers phase.
//
// TODO: this only runs Coraza's own response-header rules (CRS phase 3). DLP
// response inspection/redaction is not implemented yet: WAF is a
// request-phase concern (allow/block), while DLP is meant to be a
// response-phase concern (redact/mask/block sensitive data such as PII/PAN/
// secrets before it leaves the cluster, see docs/processor.md), and that
// response-phase engine doesn't exist yet.
func (s *Server) processResponseHeaders(ctx context.Context, state *requestState, headers *envoy_service_ext_proc_v3.HttpHeaders) *envoy_service_ext_proc_v3.ProcessingResponse {
	if state.tx == nil || headers == nil || headers.GetHeaders() == nil {
		return continueResponseHeaders()
	}

	statusCode := 0
	for _, header := range headers.GetHeaders().GetHeaders() {
		if header != nil && header.GetKey() == ":status" {
			statusCode, _ = strconv.Atoi(string(header.GetRawValue()))
		}
	}

	if interruption := state.tx.ProcessResponseHeaders(statusCode, httpProtocol); interruption != nil {
		return s.blockAndClose(ctx, state, interruption)
	}

	return continueResponseHeaders()
}

// processResponseBody handles the response-body phase.
//
// TODO: this only runs Coraza's own response-body rules (CRS phase 4). DLP
// response redaction/masking/mutation is not implemented yet (see
// docs/processor.md) - this phase currently only blocks, it never mutates
// the response body.
func (s *Server) processResponseBody(ctx context.Context, state *requestState, body *envoy_service_ext_proc_v3.HttpBody) *envoy_service_ext_proc_v3.ProcessingResponse {
	if state.tx == nil {
		return continueResponseBody()
	}

	return s.processBody(ctx, state, body, continueResponseBody,
		state.tx.WriteResponseBody, state.tx.ProcessResponseBody,
		"Failed to write response body to WAF transaction", "Failed to process response body")
}

// processBody implements the shared write-chunk/end-of-stream logic used by
// both processRequestBody and processResponseBody: Coraza's WriteRequestBody/
// WriteResponseBody and ProcessRequestBody/ProcessResponseBody have
// identical signatures, so the phase-specific behavior is passed in as
// closures bound to the already-open transaction.
func (s *Server) processBody(
	ctx context.Context,
	state *requestState,
	body *envoy_service_ext_proc_v3.HttpBody,
	continueResp func() *envoy_service_ext_proc_v3.ProcessingResponse,
	write func([]byte) (*coraza_types.Interruption, int, error),
	process func() (*coraza_types.Interruption, error),
	writeErrMsg, processErrMsg string,
) *envoy_service_ext_proc_v3.ProcessingResponse {
	if body == nil {
		return continueResp()
	}

	if len(body.GetBody()) > 0 {
		if interruption, _, err := write(body.GetBody()); err != nil {
			s.logger.ErrorContext(ctx, writeErrMsg, slog.Any("error", err))
		} else if interruption != nil {
			return s.blockAndClose(ctx, state, interruption)
		}
	}

	if body.GetEndOfStream() {
		interruption, err := process()
		if err != nil {
			s.logger.ErrorContext(ctx, processErrMsg, slog.Any("error", err))
		} else if interruption != nil {
			return s.blockAndClose(ctx, state, interruption)
		}
	}

	return continueResp()
}

// blockAndClose finalizes the transaction and builds the ImmediateResponse
// that blocks the request/response for a WAF interruption.
func (s *Server) blockAndClose(ctx context.Context, state *requestState, interruption *coraza_types.Interruption) *envoy_service_ext_proc_v3.ProcessingResponse {
	s.logger.WarnContext(ctx, "WAF blocked traffic",
		slog.String("authority", state.authority),
		slog.String("path", state.path),
		slog.Int("rule_id", interruption.RuleID),
		slog.String("action", interruption.Action))

	resp := blockResponse(interruption)
	state.closeTransaction(ctx, s.logger)
	return resp
}
