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
// TODO(user): this currently only satisfies the base scaffold. The real
// reconciliation logic (see gateway-protector-design.md, section 11.2) still
// needs to:
//   - resolve targetRef against the Gateway/HTTPRoute it points at and set
//     Accepted=False/TargetNotFound when it doesn't resolve
//   - detect conflicts with another WAFPolicy targeting the same attachment
//     point (oldest creationTimestamp wins) and set
//     Accepted=False/Conflicted on the loser
//   - compile the engine (Core Rule Set + customRulesRefs) and push
//     {engines, host+path map} to the processor
//   - render/reconcile the generated AgentgatewayPolicy for the target route,
//     owned by that route for GC
//   - set Accepted/Programmed conditions once the above succeeds
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
