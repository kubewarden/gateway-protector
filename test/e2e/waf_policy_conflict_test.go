package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kubewarden/gateway-protector/api/v1alpha1"
)

const (
	conflictNamespace = "httpbin-conflict"

	// Named so the lexicographic tiebreak in compareWAFPolicyPrecedence
	// (internal/controller/wafpolicy_conflicts.go) picks "a-first" as the
	// winner even if both objects land in the same CreationTimestamp
	// second (its only resolution) - mirroring the naming convention
	// wafpolicy_controller_test.go's envtest suite already uses for the
	// same reason.
	conflictWinnerName = "conflict-a-first"
	conflictLoserName  = "conflict-b-second"
)

// TestWAFPolicyConflict exercises conflict resolution between two
// WAFPolicy objects targeting the exact same attachment point (same
// Gateway, no sectionName): the older one wins (Accepted=True) and its
// engine is what's actually enforced; the newer one is rejected
// (Accepted=False/Conflicted) and never wired. Deleting the winner
// promotes the loser, and the data plane picks up the newly-promoted
// policy's engine.
//
// e2e tests share a single Kind cluster managed by TestMain and mutate
// cluster-wide resources, so assessments below must run sequentially.
func TestWAFPolicyConflict(t *testing.T) {
	f := features.New("WAFPolicy conflict resolution").
		Assess("Deploy httpbin wired through agentgateway", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			deployHTTPBinBase(ctx, t, cfg, conflictNamespace)

			return ctx
		}).
		Assess("Create two WAFPolicies targeting the same Gateway", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			targetRef := v1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      httpbinGatewayName,
				Namespace: conflictNamespace,
			}

			winner := &v1alpha1.WAFPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: conflictWinnerName, Namespace: namespace},
				Spec: v1alpha1.WAFPolicySpec{
					TargetRef:     targetRef,
					Engine:        v1alpha1.WAFEngineSpec{Mode: v1alpha1.WAFEngineModeBlocking},
					ParanoiaLevel: 1,
				},
			}
			err := cfg.Client().Resources().Create(ctx, winner)
			require.NoError(t, err, "failed to create %s", conflictWinnerName)

			loser := &v1alpha1.WAFPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: conflictLoserName, Namespace: namespace},
				Spec: v1alpha1.WAFPolicySpec{
					TargetRef:     targetRef,
					Engine:        v1alpha1.WAFEngineSpec{Mode: v1alpha1.WAFEngineModeDetection},
					ParanoiaLevel: 1,
				},
			}
			err = cfg.Client().Resources().Create(ctx, loser)
			require.NoError(t, err, "failed to create %s", conflictLoserName)

			return ctx
		}).
		Assess("The older policy wins: Accepted and Programmed", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: conflictWinnerName, Namespace: namespace}}

			err := wait.For(
				conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
					p, ok := obj.(*v1alpha1.WAFPolicy)
					return ok && apimeta.IsStatusConditionTrue(p.Status.Conditions, v1alpha1.ConditionTypeAccepted)
				}),
				wait.WithTimeout(statusTimeout),
			)
			require.NoError(t, err, "%s never became Accepted", conflictWinnerName)

			cond := apimeta.FindStatusCondition(policy.Status.Conditions, v1alpha1.ConditionTypeAccepted)
			require.NotNil(t, cond)
			assert.Equal(t, v1alpha1.ConditionReasonAccepted, cond.Reason)

			err = wait.For(
				conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
					p, ok := obj.(*v1alpha1.WAFPolicy)
					return ok && apimeta.IsStatusConditionTrue(p.Status.Conditions, v1alpha1.ConditionTypeProgrammed)
				}),
				wait.WithTimeout(statusTimeout),
			)
			require.NoError(t, err, "%s never became Programmed", conflictWinnerName)

			return ctx
		}).
		Assess("The newer policy loses: Accepted=False/Conflicted", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: conflictLoserName, Namespace: namespace}}

			err := wait.For(
				conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
					p, ok := obj.(*v1alpha1.WAFPolicy)
					if !ok {
						return false
					}

					cond := apimeta.FindStatusCondition(p.Status.Conditions, v1alpha1.ConditionTypeAccepted)

					return cond != nil && cond.Status == metav1.ConditionFalse
				}),
				wait.WithTimeout(statusTimeout),
			)
			require.NoError(t, err, "%s never became Accepted=False", conflictLoserName)

			cond := apimeta.FindStatusCondition(policy.Status.Conditions, v1alpha1.ConditionTypeAccepted)
			require.NotNil(t, cond)
			assert.Equal(t, v1alpha1.ConditionReasonConflicted, cond.Reason)
			assert.Contains(t, cond.Message, "gateway-protector-system/"+conflictWinnerName)

			return ctx
		}).
		Assess("Traffic is protected by the winner's engine (Blocking)", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, conflictNamespace, "", "/get"+maliciousQuery, "403", trafficTimeout)

			return ctx
		}).
		Assess("Deleting the winner promotes the loser", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			winner := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: conflictWinnerName, Namespace: namespace}}
			err := cfg.Client().Resources().Delete(ctx, winner)
			require.NoError(t, err, "failed to delete %s", conflictWinnerName)

			policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: conflictLoserName, Namespace: namespace}}
			err = wait.For(
				conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
					p, ok := obj.(*v1alpha1.WAFPolicy)
					return ok && apimeta.IsStatusConditionTrue(p.Status.Conditions, v1alpha1.ConditionTypeAccepted)
				}),
				wait.WithTimeout(statusTimeout),
			)
			require.NoError(t, err, "%s was never promoted to Accepted after the winner was deleted", conflictLoserName)

			cond := apimeta.FindStatusCondition(policy.Status.Conditions, v1alpha1.ConditionTypeAccepted)
			require.NotNil(t, cond)
			assert.Equal(t, v1alpha1.ConditionReasonAccepted, cond.Reason)

			return ctx
		}).
		Assess("Traffic now reflects the promoted policy's engine (Detection: no longer blocked)", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, conflictNamespace, "", "/get"+maliciousQuery, "200", trafficTimeout)

			return ctx
		}).
		Teardown(func(ctx context.Context, _ *testing.T, cfg *envconf.Config) context.Context {
			nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: conflictNamespace}}
			_ = cfg.Client().Resources().Delete(ctx, nsObj)

			for _, name := range []string{conflictWinnerName, conflictLoserName} {
				policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
				_ = cfg.Client().Resources().Delete(ctx, policy)
			}

			return ctx
		})

	testenv.Test(t, f.Feature())
}
