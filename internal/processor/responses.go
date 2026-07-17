package processor

import (
	"fmt"

	coraza_types "github.com/corazawaf/coraza/v3/types"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// defaultBlockStatusCode is used when a Coraza interruption doesn't specify
// an explicit status code (e.g. a "drop" action rather than "deny,status:xxx").
const defaultBlockStatusCode = 403

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

func continueRequestBody() *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_RequestBody{
			RequestBody: &envoy_service_ext_proc_v3.BodyResponse{
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

func continueResponseBody() *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseBody{
			ResponseBody: &envoy_service_ext_proc_v3.BodyResponse{
				Response: &envoy_service_ext_proc_v3.CommonResponse{
					Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

// blockResponse builds an ImmediateResponse that terminates the
// request/response with the interruption's status code (or
// defaultBlockStatusCode if unset). An ImmediateResponse short-circuits the
// request/response entirely: it is sent back to the client directly instead
// of the request/response being forwarded to/from the upstream.
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
				Body: fmt.Appendf(nil, "Request blocked by WAF - Rule ID: %d, Action: %s", interruption.RuleID, interruption.Action),
				Headers: &envoy_service_ext_proc_v3.HeaderMutation{
					SetHeaders: []*envoy_config_core_v3.HeaderValueOption{
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:      "content-type",
								RawValue: []byte("text/plain"),
							},
							Append: &wrapperspb.BoolValue{Value: false},
						},
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
