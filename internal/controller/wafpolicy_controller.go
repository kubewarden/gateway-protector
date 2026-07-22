package controller

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// WAFPolicyReconciler reconciles a WAFPolicy object
type WAFPolicyReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafpolicies,verbs=get;list;watch;create;update;patch;delete,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafpolicies/status,verbs=get;update;patch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafpolicies/finalizers,verbs=update,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafrulesets,verbs=get;list;watch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways;httproutes,verbs=get;list;watch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// This resolves the Accepted condition only (conflict detection, targetRef
// resolution, customRulesRefs resolution); Programmed is owned by
// ProcessorConfigReconciler (see processor_config_reconciler.go) from the
// moment a policy becomes Accepted onward - this reconciler only ever sets
// Programmed=False/Pending while a policy is *not* Accepted, and otherwise
// leaves it untouched. Specifically:
//
//   - conflict detection: if another WAFPolicy targets the very same
//     attachment point (same Gateway, or same HTTPRoute + optional
//     sectionName), that is a conflict - not to be confused with a Gateway
//     policy being overridden by a Route policy, which is the intended
//     most-specific-wins behavior, not a conflict. On a genuine conflict the
//     older object (by creationTimestamp) wins and the newer one gets
//     Accepted=False/Conflicted; the previously accepted engine keeps
//     running unchanged (nothing else about the losing policy is touched)
//   - targetRef resolution: the targetRef is resolved against the live
//     Gateway/HTTPRoute it points at (verifying sectionName too, when set);
//     Accepted=False/TargetNotFound when it doesn't resolve
//   - customRulesRefs resolution: every referenced WAFRuleSet must exist in
//     the same namespace; Accepted=False/Invalid when one doesn't
//   - once all of the above succeed, Accepted=True/Accepted; Programmed is
//     left as-is (ProcessorConfigReconciler, watching WAFPolicy changes
//     itself, sets it shortly after)
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/reconcile
func (r *WAFPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	policy := &gwpv1alpha1.WAFPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("failed to get WAFPolicy %s: %w", req.NamespacedName, err)
	}

	winner, err := r.findConflictWinner(ctx, policy)
	if err != nil {
		return ctrl.Result{}, err
	}

	if namespacedName(winner) != namespacedName(policy) {
		log.Info("WAFPolicy conflicts with an earlier WAFPolicy targeting the same attachment point",
			"winner", namespacedName(winner))

		changed := setAccepted(policy, metav1.ConditionFalse, gwpv1alpha1.ConditionReasonConflicted,
			fmt.Sprintf("attachment point already claimed by WAFPolicy %s (created earlier)", namespacedName(winner)))

		return r.updateStatusIfChanged(ctx, policy, changed)
	}

	var notFound *targetNotFoundError

	if err := resolveTarget(ctx, r.Client, policy); err != nil {
		if !errors.As(err, &notFound) {
			return ctrl.Result{}, err
		}

		acceptedChanged := setAccepted(policy, metav1.ConditionFalse, gwpv1alpha1.ConditionReasonTargetNotFound, notFound.Error())
		programmedChanged := setProgrammed(policy, metav1.ConditionFalse, gwpv1alpha1.ConditionReasonPending, "targetRef not resolved")

		return r.updateStatusIfChanged(ctx, policy, acceptedChanged || programmedChanged)
	}

	if err := resolveCustomRulesRefs(ctx, r.Client, policy); err != nil {
		if !errors.As(err, &notFound) {
			return ctrl.Result{}, err
		}

		acceptedChanged := setAccepted(policy, metav1.ConditionFalse, gwpv1alpha1.ConditionReasonInvalid, notFound.Error())
		programmedChanged := setProgrammed(policy, metav1.ConditionFalse, gwpv1alpha1.ConditionReasonPending, "policy not accepted yet")

		return r.updateStatusIfChanged(ctx, policy, acceptedChanged || programmedChanged)
	}

	// Programmed is deliberately left untouched here: ProcessorConfigReconciler
	// owns it from this point on (see its doc comment), and also watches
	// WAFPolicy changes, so it will set the right value shortly after this
	// Accepted transition lands.
	changed := setAccepted(policy, metav1.ConditionTrue, gwpv1alpha1.ConditionReasonAccepted,
		"targetRef resolved and no conflicting WAFPolicy targets the same attachment point")

	return r.updateStatusIfChanged(ctx, policy, changed)
}

// updateStatusIfChanged persists policy.Status when changed is true.
func (r *WAFPolicyReconciler) updateStatusIfChanged(ctx context.Context, policy *gwpv1alpha1.WAFPolicy, changed bool) (ctrl.Result, error) {
	if !changed {
		return ctrl.Result{}, nil
	}

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update WAFPolicy %s status: %w", namespacedName(policy), err)
	}

	return ctrl.Result{}, nil
}

// findConflictWinner lists every WAFPolicy targeting the same attachment
// point as policy (via wafpolicyAttachmentIndexKey) and returns the one that
// should be Accepted (see conflictWinner in wafpolicy_conflicts.go).
func (r *WAFPolicyReconciler) findConflictWinner(ctx context.Context, policy *gwpv1alpha1.WAFPolicy) (*gwpv1alpha1.WAFPolicy, error) {
	var siblings gwpv1alpha1.WAFPolicyList
	if err := r.List(ctx, &siblings, client.MatchingFields{wafpolicyAttachmentIndexKey: attachmentKey(policy.Spec.TargetRef)}); err != nil {
		return nil, fmt.Errorf("failed to list WAFPolicies targeting the same attachment point: %w", err)
	}

	if len(siblings.Items) == 0 {
		// Should not happen: policy itself must match its own index entry.
		// Guard against a stale/inconsistent cache rather than panicking.
		return policy, nil
	}

	return conflictWinner(siblings.Items), nil
}

// mapSiblingPolicies re-enqueues every WAFPolicy targeting the same
// attachment point as obj, so that e.g. deleting the winning WAFPolicy of a
// conflict causes the losing sibling(s) to be re-evaluated and become
// Accepted.
func (r *WAFPolicyReconciler) mapSiblingPolicies(ctx context.Context, obj client.Object) []reconcile.Request {
	policy, ok := obj.(*gwpv1alpha1.WAFPolicy)
	if !ok {
		return nil
	}

	var siblings gwpv1alpha1.WAFPolicyList
	if err := r.List(ctx, &siblings, client.MatchingFields{wafpolicyAttachmentIndexKey: attachmentKey(policy.Spec.TargetRef)}); err != nil {
		logf.FromContext(ctx).Error(err, "failed to list sibling WAFPolicies")
		return nil
	}

	return requestsForPolicies(siblings.Items)
}

// mapPoliciesTargetingObject returns a handler.MapFunc that re-enqueues
// every WAFPolicy targeting the given Gateway/HTTPRoute kind + object,
// regardless of sectionName (see wafpolicyTargetIndexKey).
func (r *WAFPolicyReconciler) mapPoliciesTargetingObject(kind string) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		key := fmt.Sprintf("%s/%s/%s", kind, obj.GetNamespace(), obj.GetName())

		var policies gwpv1alpha1.WAFPolicyList
		if err := r.List(ctx, &policies, client.MatchingFields{wafpolicyTargetIndexKey: key}); err != nil {
			logf.FromContext(ctx).Error(err, "failed to list WAFPolicies targeting object", "kind", kind,
				"namespace", obj.GetNamespace(), "name", obj.GetName())

			return nil
		}

		return requestsForPolicies(policies.Items)
	}
}

// mapPoliciesReferencingRuleSet re-enqueues every WAFPolicy whose
// spec.customRulesRefs references obj (a WAFRuleSet).
func (r *WAFPolicyReconciler) mapPoliciesReferencingRuleSet(ctx context.Context, obj client.Object) []reconcile.Request {
	key := obj.GetNamespace() + "/" + obj.GetName()

	var policies gwpv1alpha1.WAFPolicyList
	if err := r.List(ctx, &policies, client.MatchingFields{wafpolicyCustomRulesRefIndexKey: key}); err != nil {
		logf.FromContext(ctx).Error(err, "failed to list WAFPolicies referencing WAFRuleSet",
			"namespace", obj.GetNamespace(), "name", obj.GetName())

		return nil
	}

	return requestsForPolicies(policies.Items)
}

func requestsForPolicies(policies []gwpv1alpha1.WAFPolicy) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(policies))
	for i := range policies {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: policies[i].Namespace, Name: policies[i].Name},
		})
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *WAFPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()

	indexers := []struct {
		key     string
		extract client.IndexerFunc
	}{
		{wafpolicyAttachmentIndexKey, indexWAFPolicyByAttachment},
		{wafpolicyTargetIndexKey, indexWAFPolicyByTarget},
		{wafpolicyCustomRulesRefIndexKey, indexWAFPolicyByCustomRulesRef},
	}

	for _, idx := range indexers {
		if err := mgr.GetFieldIndexer().IndexField(ctx, &gwpv1alpha1.WAFPolicy{}, idx.key, idx.extract); err != nil {
			return fmt.Errorf("failed to index WAFPolicy by %s: %w", idx.key, err)
		}
	}

	// GenerationChangedPredicate filters out status-only updates on every
	// watch below: this reconciler's output (Accepted) is a pure function
	// of specs plus which objects exist, never of any watched object's
	// status - so a status-only update (e.g. the gateway implementation's
	// constant HTTPRoute status churn, a sibling WAFPolicy's Accepted flip,
	// or this reconciler's own Accepted/Programmed writes triggering
	// themselves) is never relevant here, only wasteful. Create/Delete
	// events always pass through regardless (see
	// predicate.GenerationChangedPredicate's doc comment): those are what
	// actually add/remove attachment points, siblings, and targets.
	changedGeneration := builder.WithPredicates(predicate.GenerationChangedPredicate{})

	err := ctrl.NewControllerManagedBy(mgr).
		For(&gwpv1alpha1.WAFPolicy{}, changedGeneration).
		Named("wafpolicy").
		Watches(&gwpv1alpha1.WAFPolicy{}, handler.EnqueueRequestsFromMapFunc(r.mapSiblingPolicies), changedGeneration).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.mapPoliciesTargetingObject("Gateway")), changedGeneration).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapPoliciesTargetingObject("HTTPRoute")), changedGeneration).
		Watches(&gwpv1alpha1.WAFRuleSet{}, handler.EnqueueRequestsFromMapFunc(r.mapPoliciesReferencingRuleSet), changedGeneration).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create WAFPolicy controller: %w", err)
	}

	return nil
}
