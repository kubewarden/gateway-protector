package controller

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// setAccepted sets the Accepted condition on policy.Status.Conditions,
// stamping the current ObservedGeneration. It returns whether the condition
// set actually changed, so callers only issue a status update when needed.
func setAccepted(policy *gwpv1alpha1.WAFPolicy, status metav1.ConditionStatus, reason, message string) bool {
	return meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               gwpv1alpha1.ConditionTypeAccepted,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: policy.Generation,
	})
}

// setProgrammed sets the Programmed condition on policy.Status.Conditions,
// stamping the current ObservedGeneration. It returns whether the condition
// set actually changed, so callers only issue a status update when needed.
func setProgrammed(policy *gwpv1alpha1.WAFPolicy, status metav1.ConditionStatus, reason, message string) bool {
	return meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               gwpv1alpha1.ConditionTypeProgrammed,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: policy.Generation,
	})
}
