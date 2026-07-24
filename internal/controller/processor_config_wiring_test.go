package controller

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kubewarden/gateway-protector/internal/agentgatewayapi"
	"github.com/kubewarden/gateway-protector/internal/controller/processorconfig"
)

func TestWiringPolicyName(t *testing.T) {
	assert.Equal(t, "gateway-protector-shop", wiringPolicyName("shop"))
}

func TestWiringPolicyNameTruncatesLongNames(t *testing.T) {
	longA := strings.Repeat("a", 250)
	longB := strings.Repeat("a", 249) + "b"

	nameA := wiringPolicyName(longA)
	nameB := wiringPolicyName(longB)

	assert.LessOrEqual(t, len(nameA), maxObjectNameLength)
	assert.LessOrEqual(t, len(nameB), maxObjectNameLength)
	assert.NotEqual(t, nameA, nameB, "distinct route names must keep distinct policy names even after truncation")
}

func TestDesiredWiringPolicy(t *testing.T) {
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shop",
			Namespace: "team-shop",
			UID:       types.UID("route-uid"),
		},
	}

	policy := desiredWiringPolicy(processorconfig.RouteWiring{
		Route:            route,
		NeedRequestBody:  true,
		NeedResponseBody: false,
	}, "gateway-protector-system")

	// The policy must live in the route's namespace (AgentgatewayPolicy
	// targetRefs are namespace-local) and be owned by it.
	assert.Equal(t, "team-shop", policy.Namespace)
	assert.Equal(t, "gateway-protector-shop", policy.Name)
	assert.Equal(t, "true", policy.Labels[wiringManagedLabel])

	require.Len(t, policy.OwnerReferences, 1)
	owner := policy.OwnerReferences[0]
	assert.Equal(t, "HTTPRoute", owner.Kind)
	assert.Equal(t, "shop", owner.Name)
	assert.Equal(t, types.UID("route-uid"), owner.UID)

	require.Len(t, policy.Spec.TargetRefs, 1)
	target := policy.Spec.TargetRefs[0]
	assert.Equal(t, gatewayv1.Kind("HTTPRoute"), target.Kind)
	assert.Equal(t, gatewayv1.ObjectName("shop"), target.Name)
	assert.Nil(t, target.SectionName, "wiring targets the whole route; per-rule selection is the processor's job")

	require.NotNil(t, policy.Spec.Traffic)
	require.NotNil(t, policy.Spec.Traffic.ExtProc)

	backendRef := policy.Spec.Traffic.ExtProc.BackendRef
	require.NotNil(t, backendRef)
	assert.Equal(t, gatewayv1.ObjectName(ProcessorServiceName), backendRef.Name)
	assert.Equal(t, gatewayv1.Namespace("gateway-protector-system"), *backendRef.Namespace)
	assert.Equal(t, gatewayv1.PortNumber(ProcessorServicePort), *backendRef.Port)

	options := policy.Spec.Traffic.ExtProc.ProcessingOptions
	require.NotNil(t, options)
	assert.Equal(t, agentgatewayapi.HeaderSendModeSend, *options.RequestHeaderMode)
	assert.Equal(t, agentgatewayapi.HeaderSendModeSend, *options.ResponseHeaderMode)
	assert.Equal(t, agentgatewayapi.BodySendModeFullDuplexStreamed, *options.RequestBodyMode)
	assert.Equal(t, agentgatewayapi.BodySendModeNone, *options.ResponseBodyMode)
	assert.Equal(t, agentgatewayapi.TrailerSendModeSkip, *options.RequestTrailerMode)
	assert.Equal(t, agentgatewayapi.TrailerSendModeSkip, *options.ResponseTrailerMode)
}
