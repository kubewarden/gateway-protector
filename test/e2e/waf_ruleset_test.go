package e2e

import (
	"context"
	"testing"

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
	ruleSetNamespace  = "httpbin-ruleset"
	ruleSetName       = "e2e-custom-rules"
	ruleSetPolicyName = "ruleset-e2e"

	// customBlockedQuery trips the custom SecRule below, not any OWASP CRS
	// signature - proving the block comes from the referenced WAFRuleSet,
	// not from the Core Rule Set that's always compiled in alongside it.
	customBlockedQuery = "?secret=letmein"
)

// TestWAFPolicyCustomRuleSet exercises WAFPolicy.spec.customRulesRefs:
// a WAFPolicy referencing a WAFRuleSet compiles that ruleset's raw SecRule
// directives alongside the OWASP Core Rule Set, and both are enforced
// together.
//
// e2e tests share a single Kind cluster managed by TestMain and mutate
// cluster-wide resources, so assessments below must run sequentially.
func TestWAFPolicyCustomRuleSet(t *testing.T) {
	f := features.New("WAFPolicy with a custom WAFRuleSet").
		Assess("Deploy httpbin wired through agentgateway", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			deployHTTPBinBase(ctx, t, cfg, ruleSetNamespace)

			return ctx
		}).
		Assess("Create a WAFRuleSet with a custom SecRule", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			ruleSet := &v1alpha1.WAFRuleSet{
				ObjectMeta: metav1.ObjectMeta{Name: ruleSetName, Namespace: namespace},
				Spec: v1alpha1.WAFRuleSetSpec{
					Rules: []v1alpha1.WAFCustomRule{{
						ID: 10001,
						Directive: `SecRule ARGS:secret "@streq letmein" ` +
							`"id:10001,phase:2,deny,status:403,msg:'custom rule blocked'"`,
					}},
				},
			}
			err := cfg.Client().Resources().Create(ctx, ruleSet)
			require.NoError(t, err, "failed to create WAFRuleSet")

			return ctx
		}).
		Assess("Create a WAFPolicy referencing the WAFRuleSet", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := &v1alpha1.WAFPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: ruleSetPolicyName, Namespace: namespace},
				Spec: v1alpha1.WAFPolicySpec{
					TargetRef: v1alpha1.PolicyTargetReference{
						Group:     gatewayv1.GroupName,
						Kind:      "Gateway",
						Name:      httpbinGatewayName,
						Namespace: ruleSetNamespace,
					},
					Engine:          v1alpha1.WAFEngineSpec{Mode: v1alpha1.WAFEngineModeBlocking},
					ParanoiaLevel:   1,
					CustomRulesRefs: []v1alpha1.LocalRuleSetReference{{Name: ruleSetName}},
				},
			}
			err := cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err, "failed to create WAFPolicy")

			return ctx
		}).
		Assess("WAFPolicy becomes Accepted and Programmed", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: ruleSetPolicyName, Namespace: namespace}}

			err := wait.For(
				conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
					p, ok := obj.(*v1alpha1.WAFPolicy)
					return ok && apimeta.IsStatusConditionTrue(p.Status.Conditions, v1alpha1.ConditionTypeAccepted)
				}),
				wait.WithTimeout(statusTimeout),
			)
			require.NoError(t, err, "WAFPolicy never became Accepted")

			err = wait.For(
				conditions.New(cfg.Client().Resources()).ResourceMatch(policy, func(obj k8s.Object) bool {
					p, ok := obj.(*v1alpha1.WAFPolicy)
					return ok && apimeta.IsStatusConditionTrue(p.Status.Conditions, v1alpha1.ConditionTypeProgrammed)
				}),
				wait.WithTimeout(statusTimeout),
			)
			require.NoError(t, err, "WAFPolicy never became Programmed - is the custom directive failing to compile?")

			return ctx
		}).
		Assess("A request tripping the custom rule is blocked", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, ruleSetNamespace, "", "/get"+customBlockedQuery, "403", trafficTimeout)

			return ctx
		}).
		Assess("A request tripping only the OWASP CRS is also blocked", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, ruleSetNamespace, "", "/get"+maliciousQuery, "403", statusTimeout)

			return ctx
		}).
		Assess("An ordinary benign request still succeeds", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			waitForStatus(ctx, t, cfg, ruleSetNamespace, "", "/get?secret=notit", "200", statusTimeout)

			return ctx
		}).
		Teardown(func(ctx context.Context, _ *testing.T, cfg *envconf.Config) context.Context {
			nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ruleSetNamespace}}
			_ = cfg.Client().Resources().Delete(ctx, nsObj)

			policy := &v1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Name: ruleSetPolicyName, Namespace: namespace}}
			_ = cfg.Client().Resources().Delete(ctx, policy)

			ruleSet := &v1alpha1.WAFRuleSet{ObjectMeta: metav1.ObjectMeta{Name: ruleSetName, Namespace: namespace}}
			_ = cfg.Client().Resources().Delete(ctx, ruleSet)

			return ctx
		})

	testenv.Test(t, f.Feature())
}
