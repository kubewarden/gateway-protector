package controller

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kubewarden/gateway-protector/internal/agentgatewayapi"
)

// CacheOptions returns the cache.Options the manager should be constructed
// with: field-stripping transforms and (for the two Gateway API kinds this
// controller only ever reads) a UnsafeDisableDeepCopy opt-in, so the cache
// keeps less memory per watched object and List/Get avoid a defensive copy
// on every call.
//
// WAFPolicy and WAFRuleSet deliberately get neither a custom Transform nor
// UnsafeDisableDeepCopy here: this controller writes WAFPolicy.status every
// reconcile, and is expected to eventually write WAFRuleSet.status too (once
// rule validation lands) - both need an untouched, safely-copied object to
// mutate. Only managedFields (irrelevant to this controller either way) is
// stripped from them, via DefaultTransform.
//
// namespace scopes the Secret/ConfigMap cache/watch to the controller's
// own namespace (see cert_reconciler.go, the only reader/writer of
// Secrets and ConfigMaps in this controller): without a namespace field
// selector, the cache would watch these cluster-wide, requiring
// cluster-wide RBAC grants instead of namespaced ones.
func CacheOptions(namespace string) cache.Options {
	return cache.Options{
		DefaultTransform: cache.TransformStripManagedFields(),
		ByObject: map[client.Object]cache.ByObject{
			// Read-only: this controller only ever resolves targetRef
			// against a Gateway/HTTPRoute, never mutates a fetched one.
			// UnsafeDisableDeepCopy is only safe under that invariant - if
			// future code ever needs to mutate a Gateway/HTTPRoute obtained
			// from the cache, remove it for that type first.
			&gatewayv1.Gateway{}: {
				Transform:             TransformStripGateway,
				UnsafeDisableDeepCopy: new(true),
			},
			&gatewayv1.HTTPRoute{}: {
				Transform:             TransformStripHTTPRoute,
				UnsafeDisableDeepCopy: new(true),
			},
			// Only the AgentgatewayPolicy objects this controller itself
			// generates (see processor_config_wiring.go) are cached and
			// watched: the label selector keeps user-authored policies out
			// of both the cache and the watch stream entirely, so their
			// churn can never trigger a rebuild - and reconcileWiring's
			// cache-backed List cannot accidentally garbage-collect them.
			&agentgatewayapi.AgentgatewayPolicy{}: {
				Label: labels.SelectorFromSet(labels.Set{wiringManagedLabel: wiringManagedLabelValue}),
			},
			// The CA and leaf-cert Secrets cert_reconciler.go manages all
			// live in the controller's own namespace.
			&corev1.Secret{}: {
				Field: fields.OneTermEqualSelector("metadata.namespace", namespace),
			},
			// The CA-bundle ConfigMap cert_reconciler.go manages also
			// lives in the controller's own namespace.
			&corev1.ConfigMap{}: {
				Field: fields.OneTermEqualSelector("metadata.namespace", namespace),
			},
		},
	}
}

// TransformStripGateway drops fields of a cached Gateway that this
// controller never reads, to reduce the cache's memory footprint: all of
// annotations, status, and managedFields, plus every spec field except the
// handful of listener attributes actually used - a listener's name (to
// resolve a WAFPolicy's optional sectionName against it) and its hostname,
// port and protocol (to know which host/port a route attached to it
// serves). Everything else (gatewayClassName, addresses, infrastructure,
// per-listener TLS and allowedRoutes, defaultScope, ...) is dropped.
func TransformStripGateway(object any) (any, error) {
	gw, ok := object.(*gatewayv1.Gateway)
	if !ok {
		return object, fmt.Errorf("expected Gateway object, got %T", object)
	}

	gw.Annotations = nil
	gw.Status = gatewayv1.GatewayStatus{}

	strippedListeners := make([]gatewayv1.Listener, len(gw.Spec.Listeners))
	for i, listener := range gw.Spec.Listeners {
		strippedListeners[i] = gatewayv1.Listener{
			Name:     listener.Name,
			Hostname: listener.Hostname,
			Port:     listener.Port,
			Protocol: listener.Protocol,
		}
	}

	gw.Spec = gatewayv1.GatewaySpec{Listeners: strippedListeners}

	return cache.TransformStripManagedFields()(gw)
}

// TransformStripHTTPRoute drops fields of a cached HTTPRoute that this
// controller never reads, to reduce the cache's memory footprint: all of
// annotations, status, and managedFields, plus every spec field except the
// ones actually used - parentRefs and hostnames (to know which Gateway(s)
// and host(s) the route serves), and, per rule, its name (to resolve a
// WAFPolicy's optional sectionName against it) and its matches (to know
// which path(s) the rule applies to). Everything else (filters,
// backendRefs, timeouts, retry, sessionPersistence, ...) is dropped.
func TransformStripHTTPRoute(object any) (any, error) {
	route, ok := object.(*gatewayv1.HTTPRoute)
	if !ok {
		return object, fmt.Errorf("expected HTTPRoute object, got %T", object)
	}

	route.Annotations = nil
	route.Status = gatewayv1.HTTPRouteStatus{}

	strippedRules := make([]gatewayv1.HTTPRouteRule, len(route.Spec.Rules))
	for i, rule := range route.Spec.Rules {
		strippedRules[i] = gatewayv1.HTTPRouteRule{
			Name:    rule.Name,
			Matches: rule.Matches,
		}
	}

	route.Spec = gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: route.Spec.ParentRefs},
		Hostnames:       route.Spec.Hostnames,
		Rules:           strippedRules,
	}

	return cache.TransformStripManagedFields()(route)
}
