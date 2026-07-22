package controller

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// These specs exercise WAFRuleSet's schema validation
// (api/v1alpha1/wafruleset_types.go) purely at the API server level: there
// is no WAFRuleSet controller, so admission is the only enforcement point
// for these rules (dry-compile, the other enforcement point, only catches
// duplicate/malformed ids and invalid SecLang - not schema-shape problems
// like an out-of-range id, an empty rules list, or an empty directive).
var _ = Describe("WAFRuleSet", func() {
	ctx := context.Background()

	ruleSetWithID := func(name string, id int64) *gwpv1alpha1.WAFRuleSet {
		ruleSet := newTestWAFRuleSet(name)
		ruleSet.Spec.Rules[0].ID = id

		return ruleSet
	}

	DescribeTable("rejects rule ids reserved for other consumers",
		func(id int64) {
			err := k8sClient.Create(ctx, ruleSetWithID("reserved-id-ruleset", id))
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue())
		},
		Entry("zero", int64(0)),
		Entry("negative", int64(-1)),
		Entry("just above the site-local range", int64(100000)),
		Entry("OWASP Core Rule Set range", int64(900001)),
		Entry("gateway-protector's own reserved rule id", int64(10000001)),
	)

	DescribeTable("accepts rule ids within the site-local range",
		func(id int64) {
			ruleSet := ruleSetWithID("permitted-id-ruleset", id)
			Expect(k8sClient.Create(ctx, ruleSet)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, ruleSet)).To(Succeed()) })
		},
		Entry("lower boundary", int64(1)),
		Entry("upper boundary", int64(99999)),
	)

	It("reports the positive-integer and reserved-range violations with distinct messages", func() {
		var statusErr *apierrors.StatusError

		negativeErr := k8sClient.Create(ctx, ruleSetWithID("negative-id-ruleset", -1))
		Expect(negativeErr).To(HaveOccurred())
		Expect(errors.As(negativeErr, &statusErr)).To(BeTrue())
		Expect(statusErr.ErrStatus.Message).To(ContainSubstring("rule id must be a positive integer"))

		reservedErr := k8sClient.Create(ctx, ruleSetWithID("reserved-range-id-ruleset", 900001))
		Expect(reservedErr).To(HaveOccurred())
		Expect(errors.As(reservedErr, &statusErr)).To(BeTrue())
		Expect(statusErr.ErrStatus.Message).To(ContainSubstring("ids above 99999 are reserved"))
	})

	It("rejects a WAFRuleSet with no rules at all (spec.rules requires at least one entry)", func() {
		ruleSet := newTestWAFRuleSet("empty-rules-ruleset")
		ruleSet.Spec.Rules = []gwpv1alpha1.WAFCustomRule{}

		err := k8sClient.Create(ctx, ruleSet)
		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
	})

	It("rejects a rule with an empty directive", func() {
		ruleSet := newTestWAFRuleSet("empty-directive-ruleset")
		ruleSet.Spec.Rules[0].Directive = ""

		err := k8sClient.Create(ctx, ruleSet)
		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
	})

	It("accepts a realistic multi-rule WAFRuleSet", func() {
		ruleSet := &gwpv1alpha1.WAFRuleSet{
			ObjectMeta: metav1.ObjectMeta{Name: "multi-rule-ruleset", Namespace: "default"},
			Spec: gwpv1alpha1.WAFRuleSetSpec{
				Rules: []gwpv1alpha1.WAFCustomRule{
					{
						ID: 10010,
						Directive: `SecRule REQUEST_HEADERS:X-Internal-Health-Check "@streq 1" ` +
							`"id:10010,phase:1,pass,nolog,ctl:ruleEngine=Off"`,
					},
					{
						ID: 10011,
						Directive: `SecRule ARGS:promo_code "!@rx ^[A-Z0-9]{6,12}$" ` +
							`"id:10011,phase:2,deny,status:400,msg:'malformed promo code'"`,
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, ruleSet)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, ruleSet)).To(Succeed()) })
	})
})
