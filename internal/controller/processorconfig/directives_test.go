package processorconfig

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

func newTestPolicy(mode gwpv1alpha1.WAFEngineMode) *gwpv1alpha1.WAFPolicy {
	return &gwpv1alpha1.WAFPolicy{
		Spec: gwpv1alpha1.WAFPolicySpec{
			Engine: gwpv1alpha1.WAFEngineSpec{
				Mode: mode,
			},
		},
	}
}

func TestRenderDirectivesModeOff(t *testing.T) {
	policy := newTestPolicy(gwpv1alpha1.WAFEngineModeOff)

	directives := RenderDirectives(policy, nil)

	assert.Equal(t, "SecRuleEngine Off\n", directives)
}

func TestRenderDirectivesBlockingMode(t *testing.T) {
	policy := newTestPolicy(gwpv1alpha1.WAFEngineModeBlocking)

	directives := RenderDirectives(policy, nil)

	assert.Equal(t, "Include @coraza.conf-recommended\n"+
		"SecRuleEngine On\n"+
		"Include @crs-setup.conf.example\n"+
		"Include @owasp_crs/*.conf\n", directives)
}

func TestRenderDirectivesDetectionMode(t *testing.T) {
	policy := newTestPolicy(gwpv1alpha1.WAFEngineModeDetection)

	directives := RenderDirectives(policy, nil)

	assert.Equal(t, "Include @coraza.conf-recommended\n"+
		"SecRuleEngine DetectionOnly\n"+
		"Include @crs-setup.conf.example\n"+
		"Include @owasp_crs/*.conf\n", directives)
}

func TestRenderDirectivesOrdering(t *testing.T) {
	policy := newTestPolicy(gwpv1alpha1.WAFEngineModeBlocking)
	policy.Spec.ParanoiaLevel = 2
	policy.Spec.Exclusions = []gwpv1alpha1.WAFExclusion{
		{ByID: []int32{942100}},
	}

	ruleSet := &gwpv1alpha1.WAFRuleSet{
		Spec: gwpv1alpha1.WAFRuleSetSpec{
			Rules: []gwpv1alpha1.WAFCustomRule{
				{ID: 10001, Directive: `SecRule REQUEST_URI "@streq /health" "id:10001,phase:1,pass,nolog"`},
			},
		},
	}

	directives := RenderDirectives(policy, []*gwpv1alpha1.WAFRuleSet{ruleSet})

	// The full pipeline in OWASP CRS conventional order (see
	// RenderDirectives's doc comment): the paranoia override must precede
	// @crs-setup.conf.example so the setup rules honor it, and exclusions
	// must come last, after the rules they remove are loaded.
	assert.Equal(t, "Include @coraza.conf-recommended\n"+
		"SecRuleEngine On\n"+
		`SecAction "id:10000001,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=2"`+"\n"+
		"Include @crs-setup.conf.example\n"+
		"Include @owasp_crs/*.conf\n"+
		`SecRule REQUEST_URI "@streq /health" "id:10001,phase:1,pass,nolog"`+"\n"+
		"SecRuleRemoveById 942100\n", directives)
}

func TestRenderDirectivesAnomalyThreshold(t *testing.T) {
	policy := newTestPolicy(gwpv1alpha1.WAFEngineModeBlocking)
	policy.Spec.AnomalyThreshold = &gwpv1alpha1.WAFAnomalyThreshold{Inbound: 5, Outbound: 4}

	directives := RenderDirectives(policy, nil)

	assert.Contains(t, directives, "tx.inbound_anomaly_score_threshold=5")
	assert.Contains(t, directives, "tx.outbound_anomaly_score_threshold=4")
}

func TestRenderDirectivesRequestBodyEnabled(t *testing.T) {
	policy := newTestPolicy(gwpv1alpha1.WAFEngineModeBlocking)
	maxSize := resource.MustParse("1Mi")
	policy.Spec.RequestBody = &gwpv1alpha1.WAFBodyInspectionSpec{Enabled: true, MaxSize: &maxSize}

	directives := RenderDirectives(policy, nil)

	assert.Contains(t, directives, "SecRequestBodyAccess On")
	assert.Contains(t, directives, "SecRequestBodyLimit 1048576")
	assert.Contains(t, directives, "SecRequestBodyInMemoryLimit 1048576")
}

func TestRenderDirectivesRequestBodyDisabled(t *testing.T) {
	policy := newTestPolicy(gwpv1alpha1.WAFEngineModeBlocking)
	policy.Spec.RequestBody = &gwpv1alpha1.WAFBodyInspectionSpec{Enabled: false}

	directives := RenderDirectives(policy, nil)

	assert.Contains(t, directives, "SecRequestBodyAccess Off")
}

func TestRenderDirectivesResponseBody(t *testing.T) {
	policy := newTestPolicy(gwpv1alpha1.WAFEngineModeBlocking)
	policy.Spec.ResponseBody = &gwpv1alpha1.WAFBodyInspectionSpec{Enabled: false}

	directives := RenderDirectives(policy, nil)

	assert.Contains(t, directives, "SecResponseBodyAccess Off")
}

func TestRenderDirectivesCustomRuleSetOrderIsCanonical(t *testing.T) {
	policy := newTestPolicy(gwpv1alpha1.WAFEngineModeBlocking)

	ruleSetA := &gwpv1alpha1.WAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "a-ruleset"},
		Spec: gwpv1alpha1.WAFRuleSetSpec{
			Rules: []gwpv1alpha1.WAFCustomRule{{ID: 1, Directive: "SecRule A"}},
		},
	}
	ruleSetB := &gwpv1alpha1.WAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "b-ruleset"},
		Spec: gwpv1alpha1.WAFRuleSetSpec{
			Rules: []gwpv1alpha1.WAFCustomRule{{ID: 2, Directive: "SecRule B"}},
		},
	}

	// Rendering order follows namespace/name, not the order the rulesets
	// are passed in - so passing B before A must still render A before B,
	// and both input orders must render byte-for-byte identically (and so
	// share one EngineKey).
	forward := RenderDirectives(policy, []*gwpv1alpha1.WAFRuleSet{ruleSetA, ruleSetB})
	reversed := RenderDirectives(policy, []*gwpv1alpha1.WAFRuleSet{ruleSetB, ruleSetA})

	assert.Equal(t, forward, reversed, "custom ruleset rendering must not depend on input order")
	assert.Equal(t, EngineKey(forward), EngineKey(reversed))
	assert.Less(t, strings.Index(forward, "SecRule A"), strings.Index(forward, "SecRule B"))
}

func TestRenderDirectivesExclusionsAreCanonicalized(t *testing.T) {
	policy := newTestPolicy(gwpv1alpha1.WAFEngineModeBlocking)
	policy.Spec.Exclusions = []gwpv1alpha1.WAFExclusion{
		{ByID: []int32{949110}, ByTag: []string{"attack-xss"}},
		{ByID: []int32{942100}, ByTag: []string{"attack-sqli"}},
	}

	permuted := newTestPolicy(gwpv1alpha1.WAFEngineModeBlocking)
	permuted.Spec.Exclusions = []gwpv1alpha1.WAFExclusion{
		{ByID: []int32{942100, 949110}, ByTag: []string{"attack-sqli", "attack-xss"}},
	}

	// A duplicate id/tag, split across entries in yet another order, must
	// still canonicalize to the exact same rendering.
	duplicated := newTestPolicy(gwpv1alpha1.WAFEngineModeBlocking)
	duplicated.Spec.Exclusions = []gwpv1alpha1.WAFExclusion{
		{ByTag: []string{"attack-xss"}},
		{ByID: []int32{949110, 942100, 949110}},
		{ByTag: []string{"attack-sqli", "attack-xss"}},
	}

	directives := RenderDirectives(policy, nil)
	permutedDirectives := RenderDirectives(permuted, nil)
	duplicatedDirectives := RenderDirectives(duplicated, nil)

	assert.Contains(t, directives, "SecRuleRemoveById 942100 949110\n")
	assert.Contains(t, directives, "SecRuleRemoveByTag \"attack-sqli\"\nSecRuleRemoveByTag \"attack-xss\"\n")
	assert.Equal(t, directives, permutedDirectives)
	assert.Equal(t, directives, duplicatedDirectives)
	assert.Equal(t, EngineKey(directives), EngineKey(permutedDirectives))
	assert.Equal(t, EngineKey(directives), EngineKey(duplicatedDirectives))
}

func TestEngineKeyIsDeterministicAndDistinguishesContent(t *testing.T) {
	a := EngineKey("SecRuleEngine On\n")
	b := EngineKey("SecRuleEngine On\n")
	c := EngineKey("SecRuleEngine Off\n")

	assert.Equal(t, a, b, "identical directives must produce the same engine key")
	assert.NotEqual(t, a, c, "different directives must produce different engine keys")
	assert.Len(t, a, engineKeyLength)
}
