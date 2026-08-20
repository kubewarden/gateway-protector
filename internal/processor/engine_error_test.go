package processor

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	coraza_types "github.com/corazawaf/coraza/v3/types"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// erroringTransaction is a coraza_types.Transaction fake used to simulate an
// internal Coraza engine failure (an error return, as opposed to a rule
// interruption) from the body-inspecting methods. It embeds the interface
// with a nil value so any method this test doesn't expect to be called
// panics loudly instead of silently doing nothing; every method a handler
// under test is expected to reach is overridden below.
type erroringTransaction struct {
	coraza_types.Transaction

	writeRequestErr    error
	processRequestErr  error
	writeResponseErr   error
	processResponseErr error

	// processRequestInterruption/processResponseInterruption are
	// returned by Process{Request,Response}Body when the corresponding
	// err field above is nil - used to simulate a rule blocking at
	// end-of-stream without it looking like an engine error.
	processRequestInterruption  *coraza_types.Interruption
	processResponseInterruption *coraza_types.Interruption

	// requestBodyInaccessible/responseBodyInaccessible default to false
	// (i.e. accessible, matching most engines) so existing tests that
	// don't set them keep exercising the write path; set to true to
	// simulate SecRequestBodyAccess/SecResponseBodyAccess Off.
	requestBodyInaccessible  bool
	responseBodyInaccessible bool

	// requestWriteCalls/requestProcessCalls (and their response
	// counterparts) count invocations, so a test can assert a call was
	// skipped (e.g. write, when the body isn't accessible) or that a
	// phase still ran exactly once.
	requestWriteCalls    int
	requestProcessCalls  int
	responseWriteCalls   int
	responseProcessCalls int
}

func (e *erroringTransaction) WriteRequestBody(b []byte) (*coraza_types.Interruption, int, error) {
	e.requestWriteCalls++
	if e.writeRequestErr != nil {
		return nil, 0, e.writeRequestErr
	}

	return nil, len(b), nil
}

func (e *erroringTransaction) ProcessRequestBody() (*coraza_types.Interruption, error) {
	e.requestProcessCalls++
	if e.processRequestErr != nil {
		return nil, e.processRequestErr
	}

	return e.processRequestInterruption, nil
}

func (e *erroringTransaction) WriteResponseBody(b []byte) (*coraza_types.Interruption, int, error) {
	e.responseWriteCalls++
	if e.writeResponseErr != nil {
		return nil, 0, e.writeResponseErr
	}

	return nil, len(b), nil
}

func (e *erroringTransaction) ProcessResponseBody() (*coraza_types.Interruption, error) {
	e.responseProcessCalls++
	if e.processResponseErr != nil {
		return nil, e.processResponseErr
	}

	return e.processResponseInterruption, nil
}

func (e *erroringTransaction) IsRequestBodyAccessible() bool { return !e.requestBodyInaccessible }

func (e *erroringTransaction) IsResponseBodyAccessible() bool { return !e.responseBodyInaccessible }

func (e *erroringTransaction) ProcessLogging() {}

func (e *erroringTransaction) Close() error { return nil }

// assertInternalErrorResponse asserts that resp is the ImmediateResponse
// failAndClose/internalErrorResponse build for a Coraza engine error: a
// plain 500 with no body and, unlike a rule block, no x-waf-violation
// header (that marker means a rule matched, and none did here).
func assertInternalErrorResponse(t *testing.T, resp *envoy_service_ext_proc_v3.ProcessingResponse) {
	t.Helper()

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{}, resp.GetResponse())
	immediate := resp.GetImmediateResponse()

	assert.EqualValues(t, 500, immediate.GetStatus().GetCode())
	assert.Empty(t, immediate.GetBody())

	for _, opt := range immediate.GetHeaders().GetSetHeaders() {
		assert.NotEqual(t, "x-waf-violation", opt.GetHeader().GetKey(),
			"an engine error is not a rule violation and must not carry the WAF-block marker header")
	}
}

func TestProcessRequestBody_WriteErrorFailsClosed(t *testing.T) {
	s := New(nil, nil)
	state := requestState{tx: &erroringTransaction{writeRequestErr: errors.New("write boom")}}

	resp := requireSingleResponse(t, s.processRequestBody(context.Background(), &state,
		&envoy_service_ext_proc_v3.HttpBody{Body: []byte("payload")}))

	assertInternalErrorResponse(t, resp)
	assert.Nil(t, state.tx, "transaction must be closed on engine error")
}

func TestProcessRequestBody_ProcessErrorFailsClosed(t *testing.T) {
	s := New(nil, nil)
	state := requestState{tx: &erroringTransaction{processRequestErr: errors.New("process boom")}}

	resp := requireSingleResponse(t, s.processRequestBody(context.Background(), &state,
		&envoy_service_ext_proc_v3.HttpBody{EndOfStream: true}))

	assertInternalErrorResponse(t, resp)
	assert.Nil(t, state.tx)
}

func TestProcessResponseBody_WriteErrorFailsClosed(t *testing.T) {
	s := New(nil, nil)
	state := requestState{tx: &erroringTransaction{writeResponseErr: errors.New("write boom")}}

	resp := requireSingleResponse(t, s.processResponseBody(context.Background(), &state,
		&envoy_service_ext_proc_v3.HttpBody{Body: []byte("payload")}))

	assertInternalErrorResponse(t, resp)
	assert.Nil(t, state.tx)
}

func TestProcessResponseBody_ProcessErrorFailsClosed(t *testing.T) {
	s := New(nil, nil)
	state := requestState{tx: &erroringTransaction{processResponseErr: errors.New("process boom")}}

	resp := requireSingleResponse(t, s.processResponseBody(context.Background(), &state,
		&envoy_service_ext_proc_v3.HttpBody{EndOfStream: true}))

	assertInternalErrorResponse(t, resp)
	assert.Nil(t, state.tx)
}

// TestProcessEndOfRequestWithNoBody_ErrorFailsClosed covers the bodyless
// (EndOfStream on the headers message) request-phase-2 path.
func TestProcessEndOfRequestWithNoBody_ErrorFailsClosed(t *testing.T) {
	s := New(nil, nil)
	state := requestState{tx: &erroringTransaction{processRequestErr: errors.New("process boom")}}

	resp := s.processEndOfRequestWithNoBody(context.Background(), &state)

	assertInternalErrorResponse(t, resp)
	assert.Nil(t, state.tx)
	assert.True(t, state.requestBody.evaluated)
}

// TestProcessEndOfResponseWithNoBody_ErrorFailsClosed is
// TestProcessEndOfRequestWithNoBody_ErrorFailsClosed's response-phase
// counterpart.
func TestProcessEndOfResponseWithNoBody_ErrorFailsClosed(t *testing.T) {
	s := New(nil, nil)
	state := requestState{tx: &erroringTransaction{processResponseErr: errors.New("process boom")}}

	resp := s.processEndOfResponseWithNoBody(context.Background(), &state)

	assertInternalErrorResponse(t, resp)
	assert.Nil(t, state.tx)
	assert.True(t, state.responseBody.evaluated)
}

// TestProcessRequestTrailers_ErrorFailsClosed covers running the pending
// phase-2 verdict from the trailers message (see processRequestTrailers).
func TestProcessRequestTrailers_ErrorFailsClosed(t *testing.T) {
	s := New(nil, nil)
	state := requestState{tx: &erroringTransaction{processRequestErr: errors.New("process boom")}}

	resp := requireSingleResponse(t, s.processRequestTrailers(context.Background(), &state))

	assertInternalErrorResponse(t, resp)
	assert.Nil(t, state.tx)
}

// TestProcessResponseTrailers_ErrorFailsClosed is
// TestProcessRequestTrailers_ErrorFailsClosed's response-phase
// counterpart.
func TestProcessResponseTrailers_ErrorFailsClosed(t *testing.T) {
	s := New(nil, nil)
	state := requestState{tx: &erroringTransaction{processResponseErr: errors.New("process boom")}}

	resp := requireSingleResponse(t, s.processResponseTrailers(context.Background(), &state))

	assertInternalErrorResponse(t, resp)
	assert.Nil(t, state.tx)
}

// TestProcessResponseHeaders_RequestBodyCatchUpErrorFailsClosed covers the
// lazy phase-2 evaluation processResponseHeaders runs when the upstream
// answered before the request body finished streaming (see its doc
// comment): an engine error there must also fail closed, before any
// response-phase processing happens.
func TestProcessResponseHeaders_RequestBodyCatchUpErrorFailsClosed(t *testing.T) {
	s := New(nil, nil)
	state := requestState{tx: &erroringTransaction{processRequestErr: errors.New("process boom")}}

	resp := requireSingleResponse(t, s.processResponseHeaders(context.Background(), &state, httpHeaders(kv{":status", "200"})))

	assertInternalErrorResponse(t, resp)
	assert.Nil(t, state.tx)
}

// TestProcessRequestBody_InaccessibleBodySkipsWriteButStillEvaluatesAtEndOfStream
// is a regression test: WriteRequestBody silently no-ops when
// SecRequestBodyAccess is Off (Coraza returns (nil, 0, nil), the same
// shape as a body-limit ProcessPartial short write), which used to be
// misread as "the phase already ran and found nothing" - skipping the
// end-of-stream ProcessRequestBody call entirely, and with it every
// phase-2 rule that doesn't need the body itself (e.g. ARGS/query-string
// signature rules). write must now be skipped outright when the body
// isn't accessible, and the phase must still be evaluated at
// end-of-stream.
func TestProcessRequestBody_InaccessibleBodySkipsWriteButStillEvaluatesAtEndOfStream(t *testing.T) {
	s := New(nil, nil)
	tx := &erroringTransaction{
		requestBodyInaccessible:    true,
		writeRequestErr:            errors.New("write must not be called when the request body is inaccessible"),
		processRequestInterruption: &coraza_types.Interruption{RuleID: 9999, Status: 403, Action: "deny"},
	}
	state := requestState{tx: tx}

	resp := requireSingleResponse(t, s.processRequestBody(context.Background(), &state,
		&envoy_service_ext_proc_v3.HttpBody{Body: []byte("arg=<script>alert(1)</script>"), EndOfStream: true}))

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{}, resp.GetResponse())
	assert.EqualValues(t, 403, resp.GetImmediateResponse().GetStatus().GetCode())
	assert.Equal(t, 0, tx.requestWriteCalls, "write must be skipped when the body isn't accessible")
	assert.Equal(t, 1, tx.requestProcessCalls, "the phase-2 verdict must still run at end-of-stream")
	assert.Nil(t, state.tx)
}

// TestProcessResponseBody_InaccessibleBodySkipsWriteButStillEvaluatesAtEndOfStream
// is TestProcessRequestBody_InaccessibleBodySkipsWriteButStillEvaluatesAtEndOfStream's
// response-phase counterpart.
func TestProcessResponseBody_InaccessibleBodySkipsWriteButStillEvaluatesAtEndOfStream(t *testing.T) {
	s := New(nil, nil)
	tx := &erroringTransaction{
		responseBodyInaccessible:    true,
		writeResponseErr:            errors.New("write must not be called when the response body is inaccessible"),
		processResponseInterruption: &coraza_types.Interruption{RuleID: 9999, Status: 403, Action: "deny"},
	}
	state := requestState{tx: tx}

	resp := requireSingleResponse(t, s.processResponseBody(context.Background(), &state,
		&envoy_service_ext_proc_v3.HttpBody{Body: []byte("leaked-secret"), EndOfStream: true}))

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{}, resp.GetResponse())
	assert.EqualValues(t, 403, resp.GetImmediateResponse().GetStatus().GetCode())
	assert.Equal(t, 0, tx.responseWriteCalls, "write must be skipped when the body isn't accessible")
	assert.Equal(t, 1, tx.responseProcessCalls, "the phase-4 verdict must still run at end-of-stream")
	assert.Nil(t, state.tx)
}

// TestCloseTransaction_DiscardsWithheldBodyState is a regression test for
// the memory-retention concern that motivated bodyPhaseState.discard: a
// block/fail response supersedes the whole stream, so any chunks (and, on
// the response side, the deferred headers answer) still withheld at that
// point are no longer owed a response and must not be kept referenced
// until the ext_proc stream itself closes.
func TestCloseTransaction_DiscardsWithheldBodyState(t *testing.T) {
	state := requestState{
		tx: &erroringTransaction{},
		requestBody: bodyPhaseState{
			holding: true,
			held:    []heldChunk{{data: []byte("withheld request chunk")}},
		},
		responseBody: bodyPhaseState{
			holding:             true,
			heldHeadersResponse: continueResponseHeaders(),
			held:                []heldChunk{{data: []byte("withheld response chunk")}},
		},
	}

	state.closeTransaction(context.Background(), slog.Default())

	assert.False(t, state.requestBody.holding)
	assert.Nil(t, state.requestBody.held)
	assert.False(t, state.responseBody.holding)
	assert.Nil(t, state.responseBody.heldHeadersResponse)
	assert.Nil(t, state.responseBody.held)
	assert.Nil(t, state.tx)
}
