package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

func policyWithGenerationAndAccepted(generation int64, accepted metav1.ConditionStatus) *gwpv1alpha1.WAFPolicy {
	policy := &gwpv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default", Generation: generation},
	}

	if accepted != "" {
		policy.Status.Conditions = []metav1.Condition{
			{
				Type:               gwpv1alpha1.ConditionTypeAccepted,
				Status:             accepted,
				Reason:             gwpv1alpha1.ConditionReasonAccepted,
				ObservedGeneration: generation,
			},
		}
	}

	return policy
}

func TestWAFPolicyRelevantChangePredicate(t *testing.T) {
	tests := []struct {
		name string
		old  *gwpv1alpha1.WAFPolicy
		new  *gwpv1alpha1.WAFPolicy
		want bool
	}{
		{
			name: "generation changed",
			old:  policyWithGenerationAndAccepted(1, ""),
			new:  policyWithGenerationAndAccepted(2, ""),
			want: true,
		},
		{
			name: "Accepted condition appears",
			old:  policyWithGenerationAndAccepted(1, ""),
			new:  policyWithGenerationAndAccepted(1, metav1.ConditionTrue),
			want: true,
		},
		{
			name: "Accepted flips from True to False",
			old:  policyWithGenerationAndAccepted(1, metav1.ConditionTrue),
			new:  policyWithGenerationAndAccepted(1, metav1.ConditionFalse),
			want: true,
		},
		{
			name: "same generation, same Accepted status - e.g. a Programmed-only update",
			old:  policyWithGenerationAndAccepted(1, metav1.ConditionTrue),
			new:  policyWithGenerationAndAccepted(1, metav1.ConditionTrue),
			want: false,
		},
		{
			name: "neither generation nor Accepted set on either side",
			old:  policyWithGenerationAndAccepted(1, ""),
			new:  policyWithGenerationAndAccepted(1, ""),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wafPolicyRelevantChangePredicate.Update(event.UpdateEvent{
				ObjectOld: tt.old,
				ObjectNew: tt.new,
			})
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWAFPolicyRelevantChangePredicateCreateDeleteAlwaysPassThrough(t *testing.T) {
	policy := policyWithGenerationAndAccepted(1, metav1.ConditionTrue)

	assert.True(t, wafPolicyRelevantChangePredicate.Create(event.CreateEvent{Object: policy}))
	assert.True(t, wafPolicyRelevantChangePredicate.Delete(event.DeleteEvent{Object: policy}))
}
