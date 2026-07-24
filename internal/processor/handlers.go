package processor

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	coraza_types "github.com/corazawaf/coraza/v3/types"
	envoy_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// httpProtocol is used when calling into Coraza's Process{Request,Response}
// phases; ext_proc does not expose the HTTP protocol version anywhere
// meaningful for our purposes, so a constant value is used consistently for
// both phases of a given transaction. Coraza only uses it for informational
// SecLang variables (e.g. REQUEST_PROTOCOL).
const httpProtocol = "HTTP/1.1"

// headerValue returns h's value, regardless of which of the two mutually
// exclusive wire representations the ext_proc client populated: per
// envoy.config.core.v3.HeaderValue's own doc comment, "only one of `value`
// or `raw_value` can be set". agentgateway in particular sets `raw_value`
// for ordinary headers but `value` for the synthetic pseudo-headers
// (:authority, :method, :path, :status) it adds to the ext_proc payload -
// reading only GetRawValue() (as this file used to) silently sees those as
// empty, which used to make every request look like it was missing
// pseudo-headers and skip the WAF entirely.
func headerValue(h *envoy_core_v3.HeaderValue) string {
	if raw := h.GetRawValue(); len(raw) > 0 {
		return string(raw)
	}

	return h.GetValue()
}

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
			authority = headerValue(header)
		case ":method":
			method = headerValue(header)
		case ":path":
			path = headerValue(header)
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
	feedRequestHeaders(tx, headers, authority)

	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return s.blockAndClose(ctx, state, interruption)
	}

	if headers.GetEndOfStream() {
		return s.processEndOfRequestWithNoBody(ctx, state)
	}

	return continueRequestHeaders()
}

// processEndOfRequestWithNoBody runs Coraza's request-body phase (CRS
// phase 2) immediately, without waiting for a request-body ext_proc
// message that will never arrive. Per ext_proc's own protocol contract
// (see envoy.service.ext_proc.v3.HttpHeaders.end_of_stream's doc comment),
// EndOfStream == true on the headers message means "there is no message
// body associated with this request", i.e. no RequestBody message will
// ever be sent for this stream. Coraza's ARGS-inspecting signature rules
// (e.g. CRS's 941xxx XSS / 942xxx SQLi rules) only run inside
// ProcessRequestBody, so without this, any bodyless request (a GET/HEAD/
// DELETE with no body, or any request with an empty body) carrying an
// attack purely in its query string would never be evaluated at all - see
// Coraza's own doc comment on ProcessRequestBody: "It is recommended to
// call this method even if it is not expected to have a body. It permits
// to execute rules belonging to request body phase, but not necessarily
// processing the request body."
//
// If a RequestBody message somehow still arrives afterward (a protocol
// violation, since EndOfStream on the headers message rules that out),
// processRequestBody's later call to tx.ProcessRequestBody() is a safe
// no-op: Coraza tracks its own last-evaluated phase on the transaction and
// skips re-running phase-2 rules once it's already run, so no extra state
// needs to be tracked here to prevent a double evaluation.
func (s *Server) processEndOfRequestWithNoBody(ctx context.Context, state *requestState) *envoy_service_ext_proc_v3.ProcessingResponse {
	interruption, err := state.tx.ProcessRequestBody()
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to process request body", slog.Any("error", err))
	} else if interruption != nil {
		return s.blockAndClose(ctx, state, interruption)
	}

	return continueRequestHeaders()
}

// feedRequestHeaders copies headers into tx's REQUEST_HEADERS collection,
// synthesizing a "Host" header from authority when none is already present.
//
// Pseudo-headers (colon-prefixed keys: :authority, :method, :path, :scheme)
// are never fed to Coraza as literal header names, since CRS rules expect
// ordinary HTTP header names, not HTTP/2 pseudo-headers - but that means
// HTTP/2's (and ext_proc's) :authority, the only wire representation a
// Host actually arrives in, would otherwise never populate
// REQUEST_HEADERS:Host at all. Without the fallback below, the OWASP Core
// Rule Set's own REQUEST-920-PROTOCOL-ENFORCEMENT.conf rule 920280
// ("Request Missing a Host Header") fires as a false positive on every
// single request: that rule alone contributes CRS's critical_anomaly_score,
// which equals the default paranoia-level-1 inbound threshold, silently
// consuming the entire anomaly-score budget before any real attack
// signature is even evaluated.
func feedRequestHeaders(tx coraza_types.Transaction, headers *envoy_service_ext_proc_v3.HttpHeaders, authority string) {
	hasHostHeader := false

	for _, header := range headers.GetHeaders().GetHeaders() {
		if header == nil {
			continue
		}

		key := header.GetKey()
		if strings.EqualFold(key, "host") {
			hasHostHeader = true
		}

		if strings.HasPrefix(key, ":") {
			continue
		}

		tx.AddRequestHeader(key, headerValue(header))
	}

	if !hasHostHeader {
		tx.AddRequestHeader("Host", authority)
	}
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
			statusCode, _ = strconv.Atoi(headerValue(header))
		}
	}

	if interruption := state.tx.ProcessResponseHeaders(statusCode, httpProtocol); interruption != nil {
		return s.blockAndClose(ctx, state, interruption)
	}

	if headers.GetEndOfStream() {
		return s.processEndOfResponseWithNoBody(ctx, state)
	}

	return continueResponseHeaders()
}

// processEndOfResponseWithNoBody is processEndOfRequestWithNoBody's
// response-phase counterpart: EndOfStream == true on the response headers
// message (e.g. a 204 No Content, a HEAD response, or any response with an
// empty body) means no ResponseBody message will ever follow, so Coraza's
// response-body phase (CRS phase 4) rules must be run here instead. As
// with the request-phase counterpart, a ResponseBody message that
// unexpectedly still arrives afterward is handled safely by Coraza itself
// (see processEndOfRequestWithNoBody's doc comment).
func (s *Server) processEndOfResponseWithNoBody(ctx context.Context, state *requestState) *envoy_service_ext_proc_v3.ProcessingResponse {
	interruption, err := state.tx.ProcessResponseBody()
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to process response body", slog.Any("error", err))
	} else if interruption != nil {
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
