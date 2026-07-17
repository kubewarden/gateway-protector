package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

func sectionName(name string) *gatewayv1.SectionName {
	s := gatewayv1.SectionName(name)
	return &s
}

func gatewayTargetRef(namespace, name string) gwpv1alpha1.PolicyTargetReference {
	return gwpv1alpha1.PolicyTargetReference{
		Group:     gatewayv1.GroupName,
		Kind:      "Gateway",
		Name:      gatewayv1.ObjectName(name),
		Namespace: gatewayv1.Namespace(namespace),
	}
}

func TestAttachmentKey(t *testing.T) {
	base := gatewayTargetRef("infra", "shared-gw")

	withSection := base
	withSection.SectionName = sectionName("admin")

	otherKind := base
	otherKind.Kind = "HTTPRoute"

	assert.NotEqual(t, attachmentKey(base), attachmentKey(withSection), "sectionName should change the attachment key")
	assert.NotEqual(t, attachmentKey(base), attachmentKey(otherKind), "kind should change the attachment key")
	assert.Equal(t, attachmentKey(base), attachmentKey(gatewayTargetRef("infra", "shared-gw")),
		"identical refs should produce identical attachment keys")
}

func TestTargetKeyIgnoresSectionName(t *testing.T) {
	base := gatewayTargetRef("infra", "shared-gw")
	withSection := base
	withSection.SectionName = sectionName("admin")

	assert.Equal(t, targetKey(base), targetKey(withSection), "targetKey should ignore sectionName")
}

func TestConflictWinnerOldestWins(t *testing.T) {
	now := metav1.Now()
	older := gwpv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "older", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
	}
	newer := gwpv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "newer", CreationTimestamp: now},
	}

	winner := conflictWinner([]gwpv1alpha1.WAFPolicy{newer, older})
	assert.Equal(t, "ns/older", namespacedName(winner), "expected the older policy to win")

	// Order in the input slice must not matter.
	winner = conflictWinner([]gwpv1alpha1.WAFPolicy{older, newer})
	assert.Equal(t, "ns/older", namespacedName(winner), "expected the older policy to win regardless of input order")
}

func TestConflictWinnerTiebreakOnIdenticalTimestamp(t *testing.T) {
	same := metav1.Now()
	a := gwpv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "b-policy", CreationTimestamp: same},
	}
	b := gwpv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "a-policy", CreationTimestamp: same},
	}

	winner := conflictWinner([]gwpv1alpha1.WAFPolicy{a, b})
	assert.Equal(t, "ns/a-policy", namespacedName(winner),
		"expected the lexicographically smaller namespace/name to win the tiebreak")
}

func TestConflictWinnerSinglePolicy(t *testing.T) {
	only := gwpv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "only", CreationTimestamp: metav1.Now()},
	}

	winner := conflictWinner([]gwpv1alpha1.WAFPolicy{only})
	assert.Equal(t, "ns/only", namespacedName(winner), "expected the only policy to win")
}
