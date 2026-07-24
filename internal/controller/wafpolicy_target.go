package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// targetNotFoundError is returned by resolveTarget when the targetRef does
// not resolve to an existing object, or names a sectionName (listener name
// or route-rule name) that doesn't exist on an otherwise existing object.
// The message is meant to be used directly as a status condition message.
type targetNotFoundError struct {
	message string
}

// kindGateway and kindHTTPRoute are the two targetRef.kind values
// PolicyTargetReference supports (see api/v1alpha1/common_types.go's
// +kubebuilder:validation:Enum marker). sigs.k8s.io/gateway-api exports a
// Kind *type* but no constants for these two kind names, so this package
// defines its own rather than repeating the string literal at every call
// site.
const (
	kindGateway   = "Gateway"
	kindHTTPRoute = "HTTPRoute"
)

func (e *targetNotFoundError) Error() string {
	return e.message
}

// resolveTarget resolves a WAFPolicy's spec.targetRef against the live
// Gateway or HTTPRoute it points at, verifying that any sectionName also
// resolves (a listener name for Gateway, a route-rule name for HTTPRoute).
//
// It returns a *targetNotFoundError (wrapped, check with [errors.As]) when
// the target -- or its sectionName -- doesn't exist; callers should surface
// that as Accepted=False/TargetNotFound. Any other returned error is
// unexpected (e.g. a transient API server error) and should be retried.
func resolveTarget(ctx context.Context, c client.Client, policy *gwpv1alpha1.WAFPolicy) error {
	ref := policy.Spec.TargetRef

	switch ref.Kind {
	case kindGateway:
		return resolveGatewayTarget(ctx, c, ref)
	case kindHTTPRoute:
		return resolveHTTPRouteTarget(ctx, c, ref)
	default:
		// The +kubebuilder:validation:Enum marker on PolicyTargetReference.Kind
		// already restricts this at admission time, so this should be
		// unreachable in practice; guard anyway rather than silently
		// accepting an unknown kind.
		return &targetNotFoundError{message: fmt.Sprintf("unsupported targetRef.kind %q", ref.Kind)}
	}
}

func resolveGatewayTarget(ctx context.Context, c client.Client, ref gwpv1alpha1.PolicyTargetReference) error {
	gw := &gatewayv1.Gateway{}
	key := types.NamespacedName{Namespace: string(ref.Namespace), Name: string(ref.Name)}
	if err := c.Get(ctx, key, gw); err != nil {
		if apierrors.IsNotFound(err) {
			return &targetNotFoundError{
				message: fmt.Sprintf("Gateway %s not found", key),
			}
		}

		return fmt.Errorf("failed to get Gateway %s: %w", key, err)
	}

	if ref.SectionName == nil {
		return nil
	}

	for _, listener := range gw.Spec.Listeners {
		if listener.Name == *ref.SectionName {
			return nil
		}
	}

	return &targetNotFoundError{
		message: fmt.Sprintf("Gateway %s has no listener named %q", key, *ref.SectionName),
	}
}

func resolveHTTPRouteTarget(ctx context.Context, c client.Client, ref gwpv1alpha1.PolicyTargetReference) error {
	route := &gatewayv1.HTTPRoute{}
	key := types.NamespacedName{Namespace: string(ref.Namespace), Name: string(ref.Name)}
	if err := c.Get(ctx, key, route); err != nil {
		if apierrors.IsNotFound(err) {
			return &targetNotFoundError{
				message: fmt.Sprintf("HTTPRoute %s not found", key),
			}
		}

		return fmt.Errorf("failed to get HTTPRoute %s: %w", key, err)
	}

	if ref.SectionName == nil {
		return nil
	}

	for _, rule := range route.Spec.Rules {
		if rule.Name != nil && *rule.Name == *ref.SectionName {
			return nil
		}
	}

	return &targetNotFoundError{
		message: fmt.Sprintf("HTTPRoute %s has no rule named %q", key, *ref.SectionName),
	}
}

// resolveCustomRulesRefs verifies that every WAFRuleSet referenced from
// spec.customRulesRefs exists in the WAFPolicy's own namespace. It returns a
// descriptive error (meant for Accepted=False/Invalid) for the first
// unresolved reference, or nil if every reference resolves.
func resolveCustomRulesRefs(ctx context.Context, c client.Client, policy *gwpv1alpha1.WAFPolicy) error {
	for _, ruleSetRef := range policy.Spec.CustomRulesRefs {
		ruleSet := &gwpv1alpha1.WAFRuleSet{}
		key := types.NamespacedName{Namespace: policy.Namespace, Name: ruleSetRef.Name}
		if err := c.Get(ctx, key, ruleSet); err != nil {
			if apierrors.IsNotFound(err) {
				return &targetNotFoundError{
					message: fmt.Sprintf("WAFRuleSet %s not found", key),
				}
			}

			return fmt.Errorf("failed to get WAFRuleSet %s: %w", key, err)
		}
	}

	return nil
}
