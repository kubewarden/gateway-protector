// Package v1alpha1 contains the controller's webhooks.
//
// +kubebuilder:webhookconfiguration:mutating=true,name=`{{ include "gateway-protector.fullname" . }}-controller-webhook`
// +kubebuilder:webhookconfiguration:mutating=false,name=`{{ include "gateway-protector.fullname" . }}-controller-webhook-validating`
package v1alpha1
