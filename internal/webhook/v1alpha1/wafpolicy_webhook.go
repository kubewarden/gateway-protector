package v1alpha1

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// SetupWAFPolicyWebhookWithManager registers the webhook for WAFPolicy in the manager.
func SetupWAFPolicyWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr, &gwpv1alpha1.WAFPolicy{}).
		WithValidator(&WAFPolicyCustomValidator{
			logger: mgr.GetLogger().WithName("wafpolicy_validator"),
		}).
		WithDefaulter(&WAFPolicyCustomDefaulter{
			logger: mgr.GetLogger().WithName("wafpolicy_defaulter"),
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed to setup WAFPolicy webhook: %w", err)
	}

	return nil
}

// +kubebuilder:webhook:path=/mutate-gateway-protector-kubewarden-io-v1alpha1-wafpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=gateway-protector.kubewarden.io,resources=wafpolicies,verbs=create;update,versions=v1alpha1,name=mwafpolicy-v1alpha1.kb.io,admissionReviewVersions=v1,serviceName=`{{ include "gateway-protector.fullname" . }}-controller-webhook`,serviceNamespace=`{{ .Release.Namespace }}`

// WAFPolicyCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind WAFPolicy when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type WAFPolicyCustomDefaulter struct {
	logger logr.Logger
}

var _ admission.Defaulter[*gwpv1alpha1.WAFPolicy] = &WAFPolicyCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind WAFPolicy.
func (d *WAFPolicyCustomDefaulter) Default(_ context.Context, obj *gwpv1alpha1.WAFPolicy) error {
	d.logger.Info("Defaulting WAFPolicy", "name", obj.GetName())

	// TODO(user): this currently accepts everything unchanged. Nothing here
	// requires defaulting yet; revisit once the processor's engine-compile
	// step is implemented (e.g. it could default requestBody.maxSize when
	// requestBody.enabled is true but maxSize is unset).

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// +kubebuilder:webhook:path=/validate-gateway-protector-kubewarden-io-v1alpha1-wafpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=gateway-protector.kubewarden.io,resources=wafpolicies,verbs=create;update,versions=v1alpha1,name=vwafpolicy-v1alpha1.kb.io,admissionReviewVersions=v1,serviceName=`{{ include "gateway-protector.fullname" . }}-controller-webhook`,serviceNamespace=`{{ .Release.Namespace }}`

// WAFPolicyCustomValidator struct is responsible for validating the WAFPolicy resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type WAFPolicyCustomValidator struct {
	logger logr.Logger
}

var _ admission.Validator[*gwpv1alpha1.WAFPolicy] = &WAFPolicyCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type WAFPolicy.
//
// TODO(user): this currently accepts everything unchanged. This admission
// webhook should additionally:
//   - dry-compile the composed Coraza directives (embedded Core Rule Set +
//     paranoiaLevel + anomalyThreshold + exclusions + referenced
//     WAFRuleSet.spec.rules) and reject invalid configuration before it
//     reaches the data plane
//   - reject a duplicate targetRef: another WAFPolicy already targeting the
//     exact same attachment point (same Gateway, or same HTTPRoute + optional
//     sectionName) is a conflict, and should be a Conflicted admission-time
//     rejection rather than merely a status condition. Note this is
//     different from a Gateway-level policy being overridden by a
//     Route-level one, which is the intended most-specific-wins behavior,
//     not a conflict (see internal/controller/wafpolicy_controller.go's
//     Reconcile doc comment for the full resolution model). The
//     reconciler-side, creationTimestamp-based tiebreak in that same file
//     remains the fallback for conflicts that slip past this webhook (e.g.
//     simultaneous GitOps apply of two conflicting objects).
//
// Deliberately NOT planned here: verifying that spec.customRulesRefs
// resolves to an existing WAFRuleSet. Rejecting on a reference that doesn't
// exist yet would make `kubectl apply -f dir/` order-dependent (the
// WAFPolicy and its WAFRuleSet are typically applied together, in
// unspecified order). That referential-integrity check belongs to the
// reconciler instead, which reports it as Accepted=False/Invalid and
// re-evaluates once the missing WAFRuleSet shows up (see
// internal/controller/wafpolicy_target.go's resolveCustomRulesRefs and
// docs/wafpolicy-lifecycle.md).
func (v *WAFPolicyCustomValidator) ValidateCreate(_ context.Context, obj *gwpv1alpha1.WAFPolicy) (admission.Warnings, error) {
	v.logger.Info("Validating WAFPolicy upon creation", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type WAFPolicy.
//
// TODO(user): this currently accepts everything unchanged; see the TODO on
// ValidateCreate for the validation this should eventually perform.
func (v *WAFPolicyCustomValidator) ValidateUpdate(_ context.Context, _, newObj *gwpv1alpha1.WAFPolicy) (admission.Warnings, error) {
	v.logger.Info("Validating WAFPolicy upon update", "name", newObj.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type WAFPolicy.
func (v *WAFPolicyCustomValidator) ValidateDelete(_ context.Context, obj *gwpv1alpha1.WAFPolicy) (admission.Warnings, error) {
	v.logger.Info("Validating WAFPolicy upon deletion", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object deletion, if any
	// (deletion validation is not currently enabled; see the verbs on the
	// +kubebuilder:webhook marker above).

	return nil, nil
}
