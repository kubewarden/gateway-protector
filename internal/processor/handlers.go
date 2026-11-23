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

// singleResponse wraps a single ProcessingResponse in the slice shape
// handlers return. Handlers return a slice because agentgateway's
// FULL_DUPLEX_STREAMED mode is not a lockstep request/response protocol:
// while a body verdict is pending, received messages are answered with
// nothing at all (the chunks are withheld, see bodyPhaseState), and the
// verdict message is then answered with everything owed at once (the
// deferred headers answer plus one echo per withheld chunk).
func singleResponse(resp *envoy_service_ext_proc_v3.ProcessingResponse) []*envoy_service_ext_proc_v3.ProcessingResponse {
	return []*envoy_service_ext_proc_v3.ProcessingResponse{resp}
}

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
// WAF engine for this request from the Identity agentgateway sends in
// metadata (see identityFromMetadata and
// internal/processor/config.Snapshot.Resolve) and, if one is attached,
// starts a Coraza transaction and evaluates phase 1/2 rules. A request
// without a valid Identity fails closed.
func (s *Server) processRequestHeaders(ctx context.Context, state *requestState, headers *envoy_service_ext_proc_v3.HttpHeaders, metadata *envoy_core_v3.Metadata) []*envoy_service_ext_proc_v3.ProcessingResponse {
	if headers == nil || headers.GetHeaders() == nil {
		s.logger.WarnContext(ctx, "ext_proc sent request headers phase with no headers")
		return singleResponse(continueRequestHeaders())
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
		return singleResponse(continueRequestHeaders())
	}

	state.authority = authority
	state.path = path

	snapshot := s.snapshot.Load()
	if snapshot == nil {
		s.logger.ErrorContext(ctx, "Processor has no config loaded, skipping WAF", slog.String("authority", authority))
		return singleResponse(continueRequestHeaders())
	}

	identity, err := identityFromMetadata(metadata)
	if err != nil {
		return singleResponse(s.failAndClose(ctx, state, "Request has no valid identity in the ext_proc metadata, failing closed", err))
	}
	state.identity = identity

	waf, matched := snapshot.Resolve(identity)
	if !matched {
		s.logger.DebugContext(ctx, "No WAFPolicy applies, request is unprotected",
			slog.String("authority", authority), slog.String("path", path), slog.Any("identity", identity))
		return singleResponse(continueRequestHeaders())
	}
	if waf == nil {
		// A binding matched but has no WAF engine attached: its policy
		// failed to compile (see config.Binding.WAF).
		return singleResponse(continueRequestHeaders())
	}

	tx := waf.NewTransaction()
	state.tx = tx

	tx.ProcessURI(path, method, httpProtocol)
	feedRequestHeaders(tx, headers, authority)

	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return singleResponse(s.blockAndClose(ctx, state, interruption))
	}

	if headers.GetEndOfStream() {
		return singleResponse(s.processEndOfRequestWithNoBody(ctx, state))
	}

	// A request body will follow. When Coraza is going to inspect it
	// (SecRequestBodyAccess On), the chunks are withheld from the
	// upstream until the phase-2 verdict: streaming a malicious body
	// upstream and only then blocking the *response* would still let the
	// upstream act on the attack (e.g. execute the SQLi). agentgateway
	// explicitly supports the server buffering like this before
	// answering.
	state.requestBody.holding = tx.IsRequestBodyAccessible()

	return singleResponse(continueRequestHeaders())
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
	state.requestBody.evaluated = true

	interruption, err := state.tx.ProcessRequestBody()
	if err != nil {
		return s.failAndClose(ctx, state, "Failed to process request body", err)
	}
	if interruption != nil {
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

// processRequestBody handles one request-body chunk (see processBodyChunk
// for the shared streaming/holding logic).
func (s *Server) processRequestBody(ctx context.Context, state *requestState, body *envoy_service_ext_proc_v3.HttpBody) []*envoy_service_ext_proc_v3.ProcessingResponse {
	if state.tx == nil {
		// No WAF for this stream: echo the chunk straight through
		// (see echoRequestBody for why even unprotected chunks must
		// be echoed).
		return singleResponse(echoRequestBody(body.GetBody(), body.GetEndOfStream()))
	}

	return s.processBodyChunk(ctx, state, &state.requestBody, body, state.tx.IsRequestBodyAccessible(),
		state.tx.WriteRequestBody, state.tx.ProcessRequestBody, echoRequestBody,
		"Failed to write request body to WAF transaction", "Failed to process request body")
}

// processRequestTrailers handles a RequestTrailers message. agentgateway
// forces trailer delivery on whenever a body mode is FULL_DUPLEX_STREAMED,
// and a trailers message is one of its three end-of-body signals (the
// others being a data chunk or an empty body message with end_of_stream
// set), so an unevaluated request body phase must be evaluated here.
func (s *Server) processRequestTrailers(ctx context.Context, state *requestState) []*envoy_service_ext_proc_v3.ProcessingResponse {
	if state.tx == nil {
		return singleResponse(requestTrailersResponse())
	}

	if !state.requestBody.evaluated {
		state.requestBody.evaluated = true

		interruption, err := state.tx.ProcessRequestBody()
		if err != nil {
			return singleResponse(s.failAndClose(ctx, state, "Failed to process request body", err))
		}
		if interruption != nil {
			return singleResponse(s.blockAndClose(ctx, state, interruption))
		}
	}

	out := state.requestBody.release(echoRequestBody)

	return append(out, requestTrailersResponse())
}

// processResponseHeaders handles the response-headers phase: it copies the
// response headers into the transaction's RESPONSE_HEADERS collection and
// runs Coraza's response-header rules (CRS phase 3).
//
// Feeding the headers (not just the :status pseudo-header) matters twice
// over: RESPONSE_HEADERS-matching rules (e.g. CRS's 95x leakage rules)
// obviously need the values, but so does the *response body* phase -
// Coraza only populates RESPONSE_BODY when the response's Content-Type is
// in the SecResponseBodyMimeType allowlist, and it learns that
// Content-Type here. Without this, phase-4 rules silently never ran on
// real traffic (see test/coraza-e2e, which caught exactly that).
//
// When Coraza is going to inspect the response body, the CONTINUE answer
// to this message is *withheld* until the phase-4 verdict: agentgateway
// commits the response head downstream the moment this message is
// answered, after which an ImmediateResponse can no longer replace the
// status - blocking on the response body is only possible while the
// headers answer is still pending. Responses Coraza won't inspect (a
// Content-Type outside the SecResponseBodyMimeType allowlist, e.g.
// text/event-stream or an image) are answered immediately, so streaming
// passes through unbuffered.
//
// TODO: this only runs Coraza's own response-header rules (CRS phase 3). DLP
// response inspection/redaction is not implemented yet: WAF is a
// request-phase concern (allow/block), while DLP is meant to be a
// response-phase concern (redact/mask/block sensitive data such as PII/PAN/
// secrets before it leaves the cluster, see docs/processor.md), and that
// response-phase engine doesn't exist yet.
func (s *Server) processResponseHeaders(ctx context.Context, state *requestState, headers *envoy_service_ext_proc_v3.HttpHeaders) []*envoy_service_ext_proc_v3.ProcessingResponse {
	if state.tx == nil || headers == nil || headers.GetHeaders() == nil {
		return singleResponse(continueResponseHeaders())
	}

	// The request-body phase must have been evaluated before response
	// phases run. It normally has been by now; the exception is an
	// upstream that responded before the request body finished
	// streaming (or agentgateway aborting the request stream), in which
	// case the verdict runs on the partial body seen so far.
	if !state.requestBody.evaluated {
		state.requestBody.evaluated = true

		interruption, err := state.tx.ProcessRequestBody()
		if err != nil {
			return singleResponse(s.failAndClose(ctx, state, "Failed to process request body", err))
		}
		if interruption != nil {
			return singleResponse(s.blockAndClose(ctx, state, interruption))
		}
	}
	// Any request chunks still withheld are moot once the upstream has
	// responded; release them so agentgateway doesn't wait on their
	// answers.
	out := state.requestBody.release(echoRequestBody)

	statusCode := 0
	for _, header := range headers.GetHeaders().GetHeaders() {
		if header == nil {
			continue
		}

		key := header.GetKey()
		if key == ":status" {
			statusCode, _ = strconv.Atoi(headerValue(header))
		}

		// Pseudo-headers are not real HTTP headers; CRS rules expect
		// ordinary header names (mirroring feedRequestHeaders).
		if strings.HasPrefix(key, ":") {
			continue
		}

		state.tx.AddResponseHeader(key, headerValue(header))
	}

	if interruption := state.tx.ProcessResponseHeaders(statusCode, httpProtocol); interruption != nil {
		return singleResponse(s.blockAndClose(ctx, state, interruption))
	}

	if headers.GetEndOfStream() {
		return append(out, s.processEndOfResponseWithNoBody(ctx, state))
	}

	if state.tx.IsResponseBodyAccessible() && state.tx.IsResponseBodyProcessable() {
		state.responseBody.holding = true
		state.responseBody.heldHeadersResponse = continueResponseHeaders()

		return out
	}

	return append(out, continueResponseHeaders())
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
	state.responseBody.evaluated = true

	interruption, err := state.tx.ProcessResponseBody()
	if err != nil {
		return s.failAndClose(ctx, state, "Failed to process response body", err)
	}
	if interruption != nil {
		return s.blockAndClose(ctx, state, interruption)
	}

	return continueResponseHeaders()
}

// processResponseBody handles one response-body chunk (see processBodyChunk
// for the shared streaming/holding logic).
func (s *Server) processResponseBody(ctx context.Context, state *requestState, body *envoy_service_ext_proc_v3.HttpBody) []*envoy_service_ext_proc_v3.ProcessingResponse {
	if state.tx == nil {
		return singleResponse(echoResponseBody(body.GetBody(), body.GetEndOfStream()))
	}

	return s.processBodyChunk(ctx, state, &state.responseBody, body, state.tx.IsResponseBodyAccessible(),
		state.tx.WriteResponseBody, state.tx.ProcessResponseBody, echoResponseBody,
		"Failed to write response body to WAF transaction", "Failed to process response body")
}

// processResponseTrailers is processRequestTrailers' response-direction
// counterpart: it runs the phase-4 verdict if it hasn't run yet, then
// releases anything withheld (the deferred headers answer plus chunk
// echoes) and acknowledges the trailers.
func (s *Server) processResponseTrailers(ctx context.Context, state *requestState) []*envoy_service_ext_proc_v3.ProcessingResponse {
	if state.tx == nil {
		return singleResponse(responseTrailersResponse())
	}

	if !state.responseBody.evaluated {
		state.responseBody.evaluated = true

		interruption, err := state.tx.ProcessResponseBody()
		if err != nil {
			return singleResponse(s.failAndClose(ctx, state, "Failed to process response body", err))
		}
		if interruption != nil {
			return singleResponse(s.blockAndClose(ctx, state, interruption))
		}
	}

	out := state.responseBody.release(echoResponseBody)

	return append(out, responseTrailersResponse())
}

// processBodyChunk implements the shared per-chunk logic for both body
// directions: feed the chunk to Coraza, then either withhold it pending
// the body-phase verdict (bs.holding) or echo it straight back
// (streaming). Coraza's Write{Request,Response}Body and
// Process{Request,Response}Body have identical signatures, so the
// direction-specific behavior is passed in as closures bound to the
// already-open transaction.
//
// accessible mirrors the transaction's own
// IsRequestBodyAccessible()/IsResponseBodyAccessible() (whether
// SecRequestBodyAccess/SecResponseBodyAccess is On) and gates whether
// write is even called. This matters because Write{Request,Response}Body
// silently no-ops - returning (nil, 0, nil), i.e. a "short write" of zero
// bytes - when body access is off, which looks identical to the
// body-limit ProcessPartial short write handled below and would
// incorrectly mark the phase evaluated without ever calling process():
// phase-2/4 rules that don't need the body itself (e.g. CRS's
// ARGS/query-string signature rules) would then silently never run for
// any request/response that happens to carry a body on such an engine.
// With accessible false, write is skipped entirely and only the
// end-of-stream process() call below can evaluate the phase.
//
// An error from write/process (as opposed to an interruption) means
// Coraza itself failed to inspect the chunk - e.g. it could no longer
// buffer body bytes. That fails the request/response closed (see
// failAndClose): a malfunctioning engine must not let traffic through
// uninspected, which would hand an attacker able to trigger the failure a
// free pass around the WAF.
//
// The holding path bounds its memory via Coraza's own body limits: when
// SecRequestBodyLimit/SecResponseBodyLimit is reached with the
// ProcessPartial action, Coraza runs the body phase on the partial body
// *inside* the write (returning any interruption from it) and reports a
// short write - at which point the verdict is final, everything withheld
// is released, and the remainder of the stream flows through unbuffered.
// With the Reject action the write returns an interruption instead, which
// blocks the stream outright.
func (s *Server) processBodyChunk(
	ctx context.Context,
	state *requestState,
	bs *bodyPhaseState,
	body *envoy_service_ext_proc_v3.HttpBody,
	accessible bool,
	write func([]byte) (*coraza_types.Interruption, int, error),
	process func() (*coraza_types.Interruption, error),
	echo func([]byte, bool) *envoy_service_ext_proc_v3.ProcessingResponse,
	writeErrMsg, processErrMsg string,
) []*envoy_service_ext_proc_v3.ProcessingResponse {
	chunk := body.GetBody()
	endOfStream := body.GetEndOfStream()

	if accessible && len(chunk) > 0 && !bs.evaluated {
		interruption, written, err := write(chunk)
		switch {
		case err != nil:
			return singleResponse(s.failAndClose(ctx, state, writeErrMsg, err))
		case interruption != nil:
			return singleResponse(s.blockAndClose(ctx, state, interruption))
		case written < len(chunk):
			// Body limit reached with ProcessPartial: Coraza already
			// ran the body phase on the partial body inside the write
			// and found it clean (an interruption would have been
			// returned above). The verdict is final.
			bs.evaluated = true
		}
	}

	if endOfStream && !bs.evaluated {
		bs.evaluated = true

		interruption, err := process()
		if err != nil {
			return singleResponse(s.failAndClose(ctx, state, processErrMsg, err))
		}
		if interruption != nil {
			return singleResponse(s.blockAndClose(ctx, state, interruption))
		}
	}

	if bs.holding && !bs.evaluated {
		// Verdict still pending: withhold this chunk, answer nothing.
		bs.held = append(bs.held, heldChunk{data: chunk, endOfStream: endOfStream})

		return nil
	}

	// Verdict reached (or plain streaming): release anything withheld,
	// then echo this chunk through.
	out := bs.release(echo)

	return append(out, echo(chunk, endOfStream))
}

// blockAndClose finalizes the transaction and builds the ImmediateResponse
// that blocks the request/response for a WAF interruption. Any responses
// owed for withheld messages are superseded by the ImmediateResponse,
// which terminates the whole stream.
func (s *Server) blockAndClose(ctx context.Context, state *requestState, interruption *coraza_types.Interruption) *envoy_service_ext_proc_v3.ProcessingResponse {
	s.logger.WarnContext(ctx, "WAF blocked traffic",
		slog.String("authority", state.authority),
		slog.String("path", state.path),
		slog.Any("identity", state.identity),
		slog.Int("rule_id", interruption.RuleID),
		slog.String("action", interruption.Action))

	resp := blockResponse(interruption)
	state.closeTransaction(ctx, s.logger)
	return resp
}

// failAndClose is blockAndClose's counterpart for a failure that is not a
// rule interruption - a Coraza engine error, or a request without a valid
// identity: it finalizes the transaction (if any) and builds the
// ImmediateResponse that fails the request/response closed. We prefer
// failing closed here rather than letting the request/response through
// uninspected, which would give an attacker able to trigger the failure a
// free pass around the WAF. Any responses owed for withheld messages are
// superseded, same as blockAndClose.
func (s *Server) failAndClose(ctx context.Context, state *requestState, msg string, err error) *envoy_service_ext_proc_v3.ProcessingResponse {
	s.logger.ErrorContext(ctx, msg,
		slog.String("authority", state.authority),
		slog.String("path", state.path),
		slog.Any("identity", state.identity),
		slog.Any("error", err))

	resp := internalErrorResponse()
	state.closeTransaction(ctx, s.logger)
	return resp
}
