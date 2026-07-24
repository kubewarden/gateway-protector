package processorconfig

import (
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// RouteWiring describes the ext_proc wiring one protected HTTPRoute needs:
// which route to attach a generated AgentgatewayPolicy to, and which body
// phases the route's effective engines actually inspect (the union across
// every covered rule, so a route where only one rule needs request bodies
// still buffers them for all - agentgateway wiring is per-route, engine
// selection per-rule stays the processor's host+path table's job).
//
// A route covered only by mode: Off policies is still wired: its traffic
// flows through ext_proc and matches the explicit "off" engine (see
// offEngineDirectives), keeping the invariant that every route with an
// entry in the published table is actually reachable by the processor.
type RouteWiring struct {
	// Route is the HTTPRoute the generated AgentgatewayPolicy must target
	// (and live in the namespace of, and be owned by).
	Route *gatewayv1.HTTPRoute

	// NeedRequestBody reports whether any covered rule's effective policy
	// inspects request bodies.
	NeedRequestBody bool

	// NeedResponseBody reports whether any covered rule's effective policy
	// inspects response bodies.
	NeedResponseBody bool
}

// policyNeedsRequestBody reports whether policy's engine inspects request
// bodies: a nil requestBody spec means the Core Rule Set's recommended
// defaults apply, and @coraza.conf-recommended sets SecRequestBodyAccess
// On - so absence means "yes". A mode: Off policy inspects nothing.
func policyNeedsRequestBody(policy *gwpv1alpha1.WAFPolicy) bool {
	if policy.Spec.Engine.Mode == gwpv1alpha1.WAFEngineModeOff {
		return false
	}

	return policy.Spec.RequestBody == nil || policy.Spec.RequestBody.Enabled
}

// policyNeedsResponseBody is policyNeedsRequestBody for the response
// phase (@coraza.conf-recommended sets SecResponseBodyAccess On too).
func policyNeedsResponseBody(policy *gwpv1alpha1.WAFPolicy) bool {
	if policy.Spec.Engine.Mode == gwpv1alpha1.WAFEngineModeOff {
		return false
	}

	return policy.Spec.ResponseBody == nil || policy.Spec.ResponseBody.Enabled
}
