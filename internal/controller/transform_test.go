package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestTransformStripGateway(t *testing.T) {
	listenerName := gatewayv1.SectionName("http")
	hostname := gatewayv1.Hostname("shop.example.com")
	tlsMode := gatewayv1.TLSModeTerminate

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "shared-gw",
			Namespace:   "infra",
			Annotations: map[string]string{"some": "annotation"},
			ManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: "kubectl"},
			},
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "example",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Value: "10.0.0.1"},
			},
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{"team": "shop"},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     listenerName,
					Hostname: &hostname,
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &tlsMode,
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "shop-tls"},
						},
					},
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: new(gatewayv1.NamespacesFromAll),
						},
					},
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Value: "10.0.0.1"}},
		},
	}

	out, err := TransformStripGateway(gw)
	require.NoError(t, err)

	stripped, ok := out.(*gatewayv1.Gateway)
	require.True(t, ok)

	assert.Nil(t, stripped.Annotations, "annotations should be stripped")
	assert.Nil(t, stripped.ManagedFields, "managedFields should be stripped")
	assert.Equal(t, gatewayv1.GatewayStatus{}, stripped.Status, "status should be stripped")
	assert.Empty(t, stripped.Spec.GatewayClassName, "gatewayClassName should be stripped")
	assert.Nil(t, stripped.Spec.Addresses, "addresses should be stripped")
	assert.Nil(t, stripped.Spec.Infrastructure, "infrastructure should be stripped")

	// The fields this controller actually reads must survive.
	require.Len(t, stripped.Spec.Listeners, 1)
	listener := stripped.Spec.Listeners[0]
	assert.Equal(t, listenerName, listener.Name)
	assert.Equal(t, &hostname, listener.Hostname)
	assert.Equal(t, gatewayv1.PortNumber(443), listener.Port)
	assert.Equal(t, gatewayv1.HTTPSProtocolType, listener.Protocol)
	assert.Nil(t, listener.TLS, "listener TLS should be stripped")
	assert.Nil(t, listener.AllowedRoutes, "listener allowedRoutes should be stripped")
}

func TestTransformStripGatewayWrongType(t *testing.T) {
	_, err := TransformStripGateway(&gatewayv1.HTTPRoute{})
	require.Error(t, err)
}

func TestTransformStripHTTPRoute(t *testing.T) {
	ruleName := gatewayv1.SectionName("admin")
	hostname := gatewayv1.Hostname("shop.example.com")
	requestTimeout := gatewayv1.Duration("5s")

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "shop",
			Namespace:   "team-shop",
			Annotations: map[string]string{"some": "annotation"},
			ManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: "kubectl"},
			},
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "shared-gw"},
				},
			},
			Hostnames: []gatewayv1.Hostname{hostname},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Name: &ruleName,
					Matches: []gatewayv1.HTTPRouteMatch{
						{Path: &gatewayv1.HTTPPathMatch{Value: new("/admin")}},
					},
					Filters: []gatewayv1.HTTPRouteFilter{
						{Type: gatewayv1.HTTPRouteFilterRequestRedirect},
					},
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "shop-admin"}}},
					},
					Timeouts: &gatewayv1.HTTPRouteTimeouts{
						Request: &requestTimeout,
					},
				},
			},
		},
		Status: gatewayv1.HTTPRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{{}},
			},
		},
	}

	out, err := TransformStripHTTPRoute(route)
	require.NoError(t, err)

	stripped, ok := out.(*gatewayv1.HTTPRoute)
	require.True(t, ok)

	assert.Nil(t, stripped.Annotations, "annotations should be stripped")
	assert.Nil(t, stripped.ManagedFields, "managedFields should be stripped")
	assert.Equal(t, gatewayv1.HTTPRouteStatus{}, stripped.Status, "status should be stripped")

	// The fields this controller actually reads must survive.
	require.Len(t, stripped.Spec.ParentRefs, 1)
	assert.Equal(t, gatewayv1.ObjectName("shared-gw"), stripped.Spec.ParentRefs[0].Name)
	require.Len(t, stripped.Spec.Hostnames, 1)
	assert.Equal(t, hostname, stripped.Spec.Hostnames[0])

	require.Len(t, stripped.Spec.Rules, 1)
	rule := stripped.Spec.Rules[0]
	require.NotNil(t, rule.Name)
	assert.Equal(t, ruleName, *rule.Name)
	require.Len(t, rule.Matches, 1)
	assert.Equal(t, "/admin", *rule.Matches[0].Path.Value)
	assert.Nil(t, rule.Filters, "filters should be stripped")
	assert.Nil(t, rule.BackendRefs, "backendRefs should be stripped")
	assert.Nil(t, rule.Timeouts, "timeouts should be stripped")
}

func TestTransformStripHTTPRouteWrongType(t *testing.T) {
	_, err := TransformStripHTTPRoute(&gatewayv1.Gateway{})
	require.Error(t, err)
}
