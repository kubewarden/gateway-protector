package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	gatewayprotectorkubewardeniov1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// WAFPolicyReconciler reconciles a WAFPolicy object
type WAFPolicyReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafpolicies,verbs=get;list;watch;create;update;patch;delete,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafpolicies/status,verbs=get;update;patch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafpolicies/finalizers,verbs=update,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafcorerulesets,verbs=get;list;watch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafrulesets,verbs=get;list;watch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways;httproutes,verbs=get;list;watch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// TODO(user): this currently only satisfies the base scaffold. For each
// route-rule under a managed Gateway, the real reconciliation logic still
// needs to:
//   - resolve the effective WAFPolicy for the route: the route's own
//     targetRef if one targets it directly, otherwise the Gateway's
//     targetRef (the Gateway-level policy is the default for every route
//     under it), otherwise none - so a route may end up with no WAF engine
//     attached at all; DLPPolicy (once it exists) is resolved the same way,
//     independently
//   - detect conflicts: if two WAFPolicy objects target the very same
//     attachment point (same Gateway, or same HTTPRoute + optional
//     sectionName), that is a conflict - not to be confused with a Gateway
//     policy being overridden by a Route policy, which is the intended
//     most-specific-wins behavior, not a conflict. On a genuine conflict the
//     older object (by creationTimestamp) wins and the newer one gets
//     Accepted=False/Conflicted; the previously accepted engine keeps
//     running unchanged
//   - resolve targetRef against the Gateway/HTTPRoute it points at and set
//     Accepted=False/TargetNotFound when it doesn't resolve
//   - compile the engine (Core Rule Set version + exclusions + referenced
//     WAFRuleSet.spec.rules) and push {engines, host+path routing table} to
//     the processor's data-plane config (see docs/processor.md for that
//     config's schema)
//   - render/reconcile a generated AgentgatewayPolicy for the target route
//     (one per protected route, wiring the shared processor Service as
//     backendRef, with failureMode set to the strictest of the route's
//     effective WAF/DLP failureMode, and processingOptions as the union of
//     what WAF/DLP each need), owned by that route for garbage collection
//   - set Accepted/Programmed conditions on the WAFPolicy once the above
//     succeeds (or Conflicted on the losing side of a conflict, per above)
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/reconcile
func (r *WAFPolicyReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	_ = logf.FromContext(ctx)

	// TODO(user): your logic here

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WAFPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayprotectorkubewardeniov1alpha1.WAFPolicy{}).
		Named("wafpolicy").
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create WAFPolicy controller: %w", err)
	}

	return nil
}
