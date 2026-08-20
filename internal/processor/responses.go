package processor

import (
	coraza_types "github.com/corazawaf/coraza/v3/types"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// defaultBlockStatusCode is used when a Coraza interruption doesn't specify
// an explicit status code (e.g. a "drop" action rather than "deny,status:xxx").
const defaultBlockStatusCode = 403

// internalErrorStatusCode is used when Coraza itself fails (an error, not
// an interruption) while processing a transaction - see internalErrorResponse.
const internalErrorStatusCode = 500

func continueRequestHeaders() *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &envoy_service_ext_proc_v3.HeadersResponse{
				Response: &envoy_service_ext_proc_v3.CommonResponse{
					Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

func continueResponseHeaders() *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &envoy_service_ext_proc_v3.HeadersResponse{
				Response: &envoy_service_ext_proc_v3.CommonResponse{
					Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

// echoRequestBody builds the RequestBody answer for one full-duplex chunk,
// echoing the original bytes back so agentgateway forwards them upstream.
//
// Echoing is not optional: in FULL_DUPLEX_STREAMED mode agentgateway
// rebuilds the proxied body exclusively from the chunks the ext_proc
// server returns in BodyMutation.streamed_response - a plain CONTINUE with
// no body mutation is treated as end-of-stream, silently truncating the
// body (agentgateway's restore-original-body path explicitly excludes the
// full-duplex mode). This processor used to answer body chunks with plain
// CONTINUE, which dropped every request/response body byte on protected
// routes; Coraza's connector e2e suite (test/coraza-e2e) is what caught
// it.
func echoRequestBody(chunk []byte, endOfStream bool) *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_RequestBody{
			RequestBody: &envoy_service_ext_proc_v3.BodyResponse{
				Response: streamedBodyCommonResponse(chunk, endOfStream),
			},
		},
	}
}

// echoResponseBody is echoRequestBody's response-direction counterpart.
func echoResponseBody(chunk []byte, endOfStream bool) *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseBody{
			ResponseBody: &envoy_service_ext_proc_v3.BodyResponse{
				Response: streamedBodyCommonResponse(chunk, endOfStream),
			},
		},
	}
}

// streamedBodyCommonResponse builds the CommonResponse shared by
// echoRequestBody/echoResponseBody: a CONTINUE carrying chunk back via
// BodyMutation.streamed_response (see echoRequestBody for why this
// mutation is required rather than a plain CONTINUE).
func streamedBodyCommonResponse(chunk []byte, endOfStream bool) *envoy_service_ext_proc_v3.CommonResponse {
	return &envoy_service_ext_proc_v3.CommonResponse{
		Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
		BodyMutation: &envoy_service_ext_proc_v3.BodyMutation{
			Mutation: &envoy_service_ext_proc_v3.BodyMutation_StreamedResponse{
				StreamedResponse: &envoy_service_ext_proc_v3.StreamedBodyResponse{
					Body:        chunk,
					EndOfStream: endOfStream,
				},
			},
		},
	}
}

// requestTrailersResponse acknowledges a RequestTrailers message.
// agentgateway treats it purely as an end-of-stream signal (it ignores any
// header mutation inside), but answering with a mismatched message type
// (as the old catch-all did) is silently dropped/ignored by agentgateway
// and can leave it waiting for a terminal signal.
func requestTrailersResponse() *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &envoy_service_ext_proc_v3.TrailersResponse{},
		},
	}
}

// responseTrailersResponse is requestTrailersResponse's response-direction
// counterpart.
func responseTrailersResponse() *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &envoy_service_ext_proc_v3.TrailersResponse{},
		},
	}
}

// blockResponse builds an ImmediateResponse that terminates the
// request/response with the interruption's status code (or
// defaultBlockStatusCode if unset). An ImmediateResponse short-circuits the
// request/response entirely: it is sent back to the client directly instead
// of the request/response being forwarded to/from the upstream.
//
// The response deliberately carries no body: echoing the matched rule
// ID/action back to the client (as this used to) both discloses
// information that helps an attacker probe which rules fired (the details
// are already logged server-side, see Server.blockAndClose) and violates
// the contract Coraza's own connector e2e suite verifies (a denied request
// must produce an empty body - see test/coraza-e2e). Only the
// x-waf-violation marker header distinguishes a WAF block from an
// upstream-originated error with the same status code.
func blockResponse(interruption *coraza_types.Interruption) *envoy_service_ext_proc_v3.ProcessingResponse {
	statusCode := interruption.Status
	if statusCode == 0 {
		statusCode = defaultBlockStatusCode
	}

	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &envoy_service_ext_proc_v3.ImmediateResponse{
				Status: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode(statusCode),
				},
				Headers: &envoy_service_ext_proc_v3.HeaderMutation{
					SetHeaders: []*envoy_config_core_v3.HeaderValueOption{
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:      "x-waf-violation",
								RawValue: []byte("1"),
							},
							Append: &wrapperspb.BoolValue{Value: false},
						},
					},
				},
			},
		},
	}
}

// internalErrorResponse builds an ImmediateResponse for when Coraza itself
// fails (an engine error, not a rule interruption) while processing a
// transaction - e.g. it can no longer buffer body bytes because its
// storage is exhausted. The request/response is refused with a plain 500,
// no x-waf-violation header (that marker means a rule matched, and none
// did here) and no body: we fail closed rather than let a malfunctioning
// engine wave traffic through uninspected, which would hand an attacker
// able to trigger the failure a free pass around the WAF.
func internalErrorResponse() *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &envoy_service_ext_proc_v3.ImmediateResponse{
				Status: &envoy_type_v3.HttpStatus{
					Code: internalErrorStatusCode,
				},
			},
		},
	}
}
