package controller

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
	"github.com/kubewarden/gateway-protector/internal/agentgatewayapi"
	"github.com/kubewarden/gateway-protector/internal/controller/processorconfig"
)

// processorConfigSingletonKey is the single, fixed reconcile.Request every
// ProcessorConfigReconciler.Reconcile call uses: the processor's data-plane
// config is one global artifact derived from every Accepted WAFPolicy plus
// the Gateway/HTTPRoute objects they attach to, not a per-object one, so
// there is no natural "which object changed" request to key it by. Every
// watch this reconciler registers (see SetupWithManager) maps its event to
// this same key.
var processorConfigSingletonKey = types.NamespacedName{Name: "processor-config"}

// ProcessorConfigReconciler reconciles the processor's data-plane
// configuration: it rebuilds the full config from every Accepted WAFPolicy
// (see internal/controller/processorconfig), publishes it (see
// ConfigPublisher), and sets Programmed on each Accepted WAFPolicy
// accordingly.
//
// This is a singleton: unlike WAFPolicyReconciler, which reconciles one
// WAFPolicy per call, every event this reconciler watches - a WAFPolicy,
// WAFRuleSet, Gateway, or HTTPRoute change - re-triggers the same one
// reconcile of the entire config, since any of those objects can change
// which routes are covered or how. See docs/wafpolicy-lifecycle.md for the
// role this plays in the WAFPolicy lifecycle.
//
// Dry-compiling every distinct engine on every single reconcile would
// scale poorly once routes number in the thousands (Coraza's compile step
// costs tens of milliseconds and non-trivial allocations per engine),
// especially since most triggers (an HTTPRoute spec edit that doesn't
// change which policy covers it, for instance) don't actually change any
// engine's directives at all. compileCache (see processorconfig.CompileCache)
// memoizes compile outcomes by engine key across reconciles, so a rebuild
// where nothing relevant changed recompiles nothing.
type ProcessorConfigReconciler struct {
	client.Client

	Scheme    *runtime.Scheme
	Publisher ConfigPublisher

	// ProcessorNamespace is the namespace the processor Service
	// (ProcessorServiceName) lives in - the controller's own namespace,
	// resolved from POD_NAMESPACE in production (see
	// cmd/controller/main.go's podNamespace). Generated AgentgatewayPolicy
	// objects point their ext_proc backendRef there.
	ProcessorNamespace string

	compileCache *processorconfig.CompileCache
}

// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafpolicies,verbs=get;list;watch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafpolicies/status,verbs=get;update;patch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway-protector.kubewarden.io,resources=wafrulesets,verbs=get;list;watch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways;httproutes,verbs=get;list;watch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch,roleName=`{{ include "gateway-protector.fullname" . }}-controller`
// +kubebuilder:rbac:groups=agentgateway.dev,resources=agentgatewaypolicies,verbs=get;list;watch;create;update;patch;delete,roleName=`{{ include "gateway-protector.fullname" . }}-controller`

// Reconcile rebuilds the processor's data-plane config from every
// Accepted=True WAFPolicy in the cluster, publishes it via r.Publisher,
// converges the generated AgentgatewayPolicy wiring (one per protected
// HTTPRoute, wiring its traffic through the processor's ext_proc Service -
// see reconcileWiring), and sets Programmed on each Accepted WAFPolicy
// according to whether its composed directives compiled successfully:
//
//   - Programmed=True/Programmed once its engine is compiled and published,
//     regardless of whether it currently covers any route (an accepted
//     policy attached to a Gateway with no HTTPRoutes yet is still fully
//     live, simply unused for now)
//   - Programmed=False/CompileFailed if its composed directives (embedded
//     Core Rule Set + paranoiaLevel + anomalyThreshold + exclusions +
//     referenced WAFRuleSet.spec.rules) fail to compile; that policy - and
//     every route it would have covered - is excluded from the published
//     config, and its routes from the generated wiring, rather than
//     blocking every other policy's config from being published
//
// Programmed is otherwise left untouched here: a WAFPolicy that isn't
// Accepted keeps whatever Programmed=False/Pending WAFPolicyReconciler set
// when it stopped being Accepted (see wafpolicy_controller.go's Reconcile);
// this reconciler only ever touches Programmed for policies it actually
// considered.
func (r *ProcessorConfigReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	var policyList gwpv1alpha1.WAFPolicyList
	if err := r.List(ctx, &policyList); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list WAFPolicies: %w", err)
	}

	var ruleSetList gwpv1alpha1.WAFRuleSetList
	if err := r.List(ctx, &ruleSetList); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list WAFRuleSets: %w", err)
	}

	var gatewayList gatewayv1.GatewayList
	if err := r.List(ctx, &gatewayList); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list Gateways: %w", err)
	}

	var httpRouteList gatewayv1.HTTPRouteList
	if err := r.List(ctx, &httpRouteList); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}

	input := processorconfig.Input{
		Policies:   acceptedPolicies(policyList.Items),
		RuleSets:   toPointerSlice(ruleSetList.Items),
		Gateways:   toPointerSlice(gatewayList.Items),
		HTTPRoutes: toPointerSlice(httpRouteList.Items),
	}

	if r.compileCache == nil {
		r.compileCache = processorconfig.NewCompileCache(processorconfig.CorazaDryCompile)
	}

	buildResult := processorconfig.Build(input, r.compileCache.Compile)
	r.compileCache.Sweep()

	if err := r.Publisher.Publish(ctx, buildResult.Config); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to publish processor config: %w", err)
	}

	// Every result's status is updated even if one fails: a status-update
	// conflict on one policy (e.g. a concurrent WAFPolicyReconciler update)
	// must not stop the others from being updated. All errors are still
	// joined and returned, though, so controller-runtime requeues this
	// reconcile with backoff instead of silently leaving that one policy's
	// Programmed condition stale until some unrelated change re-triggers
	// this singleton.
	var errs []error

	if err := r.reconcileWiring(ctx, buildResult.Wiring); err != nil {
		errs = append(errs, err)
	}

	for _, result := range buildResult.PolicyResults {
		if err := r.updateProgrammed(ctx, result); err != nil {
			errs = append(errs, err)
		}
	}

	return ctrl.Result{}, errors.Join(errs...)
}

// updateProgrammed persists Programmed on result.Policy.
func (r *ProcessorConfigReconciler) updateProgrammed(ctx context.Context, result processorconfig.PolicyResult) error {
	var changed bool

	if result.Err != nil {
		changed = setProgrammed(result.Policy, metav1.ConditionFalse, gwpv1alpha1.ConditionReasonCompileFailed, result.Err.Error())
	} else {
		message := fmt.Sprintf("engine compiled and published to the processor config (%d route(s) covered)", result.RouteCount)
		changed = setProgrammed(result.Policy, metav1.ConditionTrue, gwpv1alpha1.ConditionReasonProgrammed, message)
	}

	if !changed {
		return nil
	}

	if err := r.Status().Update(ctx, result.Policy); err != nil {
		return fmt.Errorf("failed to update WAFPolicy %s Programmed condition: %w", namespacedName(result.Policy), err)
	}

	return nil
}

// acceptedPolicies returns pointers to every WAFPolicy in policies with
// Accepted=True.
func acceptedPolicies(policies []gwpv1alpha1.WAFPolicy) []*gwpv1alpha1.WAFPolicy {
	accepted := make([]*gwpv1alpha1.WAFPolicy, 0, len(policies))

	for i := range policies {
		if meta.IsStatusConditionTrue(policies[i].Status.Conditions, gwpv1alpha1.ConditionTypeAccepted) {
			accepted = append(accepted, &policies[i])
		}
	}

	return accepted
}

// toPointerSlice returns a []*T pointing into items, avoiding a copy per
// element (as would happen taking &items[i] in a loop that also appends
// items[i] itself by value).
func toPointerSlice[T any](items []T) []*T {
	ptrs := make([]*T, len(items))
	for i := range items {
		ptrs[i] = &items[i]
	}

	return ptrs
}

// enqueueProcessorConfig maps every watched event to the single
// processorConfigSingletonKey request: the published config is one global
// artifact rebuilt from all relevant objects, so which object changed
// doesn't matter.
func enqueueProcessorConfig(_ context.Context, _ client.Object) []reconcile.Request {
	return []reconcile.Request{{NamespacedName: processorConfigSingletonKey}}
}

// wafPolicyRelevantChangePredicate re-triggers ProcessorConfigReconciler on
// a WAFPolicy update only when something it actually reads changed: the
// generation (any spec field) or the Accepted condition's status. A plain
// predicate.GenerationChangedPredicate would miss the one transition this
// reconciler exists to react to - a policy becoming (or ceasing to be)
// Accepted=True is a status-only change - while passing through every
// Programmed update this same reconciler makes to itself, which would
// otherwise cause an extra no-op rebuild after every reconcile. Create and
// Delete events always pass through (the zero-value predicate.Funcs
// default).
var wafPolicyRelevantChangePredicate = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldPolicy, ok := e.ObjectOld.(*gwpv1alpha1.WAFPolicy)
		if !ok {
			return true
		}

		newPolicy, ok := e.ObjectNew.(*gwpv1alpha1.WAFPolicy)
		if !ok {
			return true
		}

		if oldPolicy.Generation != newPolicy.Generation {
			return true
		}

		return acceptedConditionStatus(oldPolicy) != acceptedConditionStatus(newPolicy)
	},
}

// acceptedConditionStatus returns policy's Accepted condition status, or
// the empty string if it has none yet.
func acceptedConditionStatus(policy *gwpv1alpha1.WAFPolicy) metav1.ConditionStatus {
	condition := meta.FindStatusCondition(policy.Status.Conditions, gwpv1alpha1.ConditionTypeAccepted)
	if condition == nil {
		return ""
	}

	return condition.Status
}

// SetupWithManager sets up the controller with the Manager.
func (r *ProcessorConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// primeCh feeds a single synthetic event into this controller's own
	// workqueue once the manager's cache has synced, so the very first
	// reconcile - which must run even with zero
	// WAFPolicy/WAFRuleSet/Gateway/HTTPRoute objects, so the processor's
	// ConfigMap gets its inert default - is triggered through the exact
	// same serialized queue as every watch-driven reconcile, rather than
	// calling Reconcile directly (which could then run concurrently with a
	// queue-driven reconcile of the very same singleton key - e.g. both
	// racing to create the same ConfigMap on a fresh install).
	primeCh := make(chan event.GenericEvent, 1)

	err := ctrl.NewControllerManagedBy(mgr).
		Named("processor-config").
		// MaxConcurrentReconciles: 1 is already controller-runtime's
		// default, and even more workers could never run the single
		// processorConfigSingletonKey concurrently (a workqueue never
		// hands the same key to two workers at once). Set explicitly
		// anyway: this reconciler's correctness (e.g. the
		// create-vs-create ConfigMap race the priming design below
		// avoids) assumes serialized reconciles, and that intent should
		// survive any future refactor of this setup.
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		WatchesRawSource(source.Channel(primeCh, handler.EnqueueRequestsFromMapFunc(enqueueProcessorConfig))).
		Watches(&gwpv1alpha1.WAFPolicy{}, handler.EnqueueRequestsFromMapFunc(enqueueProcessorConfig),
			builder.WithPredicates(wafPolicyRelevantChangePredicate)).
		Watches(&gwpv1alpha1.WAFRuleSet{}, handler.EnqueueRequestsFromMapFunc(enqueueProcessorConfig),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(enqueueProcessorConfig),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(enqueueProcessorConfig),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Generated AgentgatewayPolicy objects are watched for drift
		// repair: the cache only holds objects carrying wiringManagedLabel
		// (see CacheOptions), so this can never fire for user-authored
		// policies. Any change to a managed one - manual edit, deletion -
		// re-triggers the rebuild, whose reconcileWiring re-applies the
		// desired state.
		Watches(&agentgatewayapi.AgentgatewayPolicy{}, handler.EnqueueRequestsFromMapFunc(enqueueProcessorConfig)).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create processor-config controller: %w", err)
	}

	err = mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		if !mgr.GetCache().WaitForCacheSync(ctx) {
			return errors.New("failed to sync cache before priming the processor config")
		}

		// With primeCh's buffer of 1 and this runnable being the only
		// sender, the send below can never actually block - the ctx.Done
		// case exists so this runnable is still guaranteed to terminate
		// during manager shutdown even if those assumptions ever change
		// (a bare channel send that nothing will ever drain would
		// otherwise hang the manager's graceful shutdown).
		select {
		case primeCh <- event.GenericEvent{}:
		case <-ctx.Done():
			return fmt.Errorf("context done before priming the processor config: %w", ctx.Err())
		}

		return nil
	}))
	if err != nil {
		return fmt.Errorf("failed to register processor-config priming runnable: %w", err)
	}

	return nil
}
