package v1alpha1

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	gatewayprotectorkubewardeniov1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// log is for logging in this package.
var wafpolicylog = logf.Log.WithName("wafpolicy-resource")

// SetupWAFPolicyWebhookWithManager registers the webhook for WAFPolicy in the manager.
func SetupWAFPolicyWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr, &gatewayprotectorkubewardeniov1alpha1.WAFPolicy{}).
		WithValidator(&WAFPolicyCustomValidator{}).
		WithDefaulter(&WAFPolicyCustomDefaulter{}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed to setup WAFPolicy webhook: %w", err)
	}

	return nil
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-gateway-protector-kubewarden-io-v1alpha1-wafpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=gateway-protector.kubewarden.io,resources=wafpolicies,verbs=create;update,versions=v1alpha1,name=mwafpolicy-v1alpha1.kb.io,admissionReviewVersions=v1,serviceName=`{{ include "gateway-protector.fullname" . }}-controller-webhook`,serviceNamespace=`{{ .Release.Namespace }}`

// WAFPolicyCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind WAFPolicy when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type WAFPolicyCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind WAFPolicy.
func (d *WAFPolicyCustomDefaulter) Default(_ context.Context, obj *gatewayprotectorkubewardeniov1alpha1.WAFPolicy) error {
	wafpolicylog.Info("Defaulting for WAFPolicy", "name", obj.GetName())

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
	// TODO(user): Add more fields as needed for validation
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type WAFPolicy.
//
// TODO(user): this currently accepts everything unchanged. Per
// gateway-protector-design.md, sections 4 and 6, this should additionally:
//   - dry-compile the composed Coraza directives (Core Rule Set version +
//     exclusions + referenced WAFRuleSet.spec.rules) and reject invalid
//     configuration before it reaches the data plane
//   - verify spec.coreRuleSet.version matches a registered WAFCoreRuleSet
//   - verify every spec.customRulesRefs entry resolves to an existing
//     WAFRuleSet in the same namespace
//   - reject a duplicate targetRef: another WAFPolicy already targeting the
//     same attachment point (Gateway/HTTPRoute + optional sectionName) is a
//     Conflicted admission-time rejection, not merely a status condition
//     (see gateway-protector-design.md, section 6, "Conflicts" - the
//     reconciler-side, creationTimestamp-based tiebreak in
//     internal/controller/wafpolicy_controller.go remains the fallback for
//     conflicts that slip past this webhook, e.g. simultaneous GitOps apply)
func (v *WAFPolicyCustomValidator) ValidateCreate(_ context.Context, obj *gatewayprotectorkubewardeniov1alpha1.WAFPolicy) (admission.Warnings, error) {
	wafpolicylog.Info("Validation for WAFPolicy upon creation", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type WAFPolicy.
//
// TODO(user): this currently accepts everything unchanged; see the TODO on
// ValidateCreate for the validation this should eventually perform.
func (v *WAFPolicyCustomValidator) ValidateUpdate(_ context.Context, _, newObj *gatewayprotectorkubewardeniov1alpha1.WAFPolicy) (admission.Warnings, error) {
	wafpolicylog.Info("Validation for WAFPolicy upon update", "name", newObj.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type WAFPolicy.
func (v *WAFPolicyCustomValidator) ValidateDelete(_ context.Context, obj *gatewayprotectorkubewardeniov1alpha1.WAFPolicy) (admission.Warnings, error) {
	wafpolicylog.Info("Validation for WAFPolicy upon deletion", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object deletion, if any
	// (deletion validation is not currently enabled; see the verbs on the
	// +kubebuilder:webhook marker above).

	return nil, nil
}
