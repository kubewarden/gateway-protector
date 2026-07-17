package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

// newTestWAFPolicy builds a minimal, valid WAFPolicy targeting the given
// Gateway/HTTPRoute, ready to be further customized by callers before
// Create.
func newTestWAFPolicy(name string, targetRef gwpv1alpha1.PolicyTargetReference) *gwpv1alpha1.WAFPolicy {
	return newTestWAFPolicyInNamespace("default", name, targetRef)
}

// newTestWAFPolicyInNamespace is newTestWAFPolicy for callers that need the
// WAFPolicy to live in a namespace other than "default" (e.g. to exercise
// cross-namespace targetRef resolution).
func newTestWAFPolicyInNamespace(namespace, name string, targetRef gwpv1alpha1.PolicyTargetReference) *gwpv1alpha1.WAFPolicy {
	return &gwpv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: gwpv1alpha1.WAFPolicySpec{
			TargetRef: targetRef,
			Engine: gwpv1alpha1.WAFEngineSpec{
				Mode:        gwpv1alpha1.WAFEngineModeBlocking,
				FailureMode: gwpv1alpha1.FailureModeClosed,
			},
			ParanoiaLevel: 1,
		},
	}
}

// newTestGateway builds a minimal, valid Gateway; a single "http" listener
// on port 80 is used when no listeners are given.
func newTestGateway(namespace, name string, listeners ...gatewayv1.Listener) *gatewayv1.Gateway {
	if len(listeners) == 0 {
		listeners = []gatewayv1.Listener{
			{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		}
	}

	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "example",
			Listeners:        listeners,
		},
	}
}

// newTestHTTPRoute builds a minimal, valid HTTPRoute in the "default"
// namespace; a single unnamed rule is used when no rules are given.
func newTestHTTPRoute(name string, rules ...gatewayv1.HTTPRouteRule) *gatewayv1.HTTPRoute {
	if len(rules) == 0 {
		rules = []gatewayv1.HTTPRouteRule{{}}
	}

	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       gatewayv1.HTTPRouteSpec{Rules: rules},
	}
}

// newTestWAFRuleSet builds a minimal, valid WAFRuleSet (spec.rules requires
// at least one entry).
func newTestWAFRuleSet(namespace, name string) *gwpv1alpha1.WAFRuleSet {
	return &gwpv1alpha1.WAFRuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: gwpv1alpha1.WAFRuleSetSpec{
			Rules: []gwpv1alpha1.WAFCustomRule{
				{ID: 1000001, Directive: `SecRule &REQUEST_HEADERS "@eq 0" "id:1000001,phase:1,pass,nolog"`},
			},
		},
	}
}

func acceptedCondition(policy *gwpv1alpha1.WAFPolicy) *metav1.Condition {
	return meta.FindStatusCondition(policy.Status.Conditions, gwpv1alpha1.ConditionTypeAccepted)
}

func programmedCondition(policy *gwpv1alpha1.WAFPolicy) *metav1.Condition {
	return meta.FindStatusCondition(policy.Status.Conditions, gwpv1alpha1.ConditionTypeProgrammed)
}

func fetchPolicy(ctx context.Context, key types.NamespacedName) func() *gwpv1alpha1.WAFPolicy {
	return func() *gwpv1alpha1.WAFPolicy {
		policy := &gwpv1alpha1.WAFPolicy{}
		if err := k8sClient.Get(ctx, key, policy); err != nil {
			return nil
		}

		return policy
	}
}

func fetchAccepted(ctx context.Context, key types.NamespacedName) func() *metav1.Condition {
	return func() *metav1.Condition {
		policy := fetchPolicy(ctx, key)()
		if policy == nil {
			return nil
		}

		return acceptedCondition(policy)
	}
}

func acceptedStatus(ctx context.Context, key types.NamespacedName) func() metav1.ConditionStatus {
	return func() metav1.ConditionStatus {
		condition := fetchAccepted(ctx, key)()
		if condition == nil {
			return ""
		}

		return condition.Status
	}
}

func acceptedReason(ctx context.Context, key types.NamespacedName) func() string {
	return func() string {
		condition := fetchAccepted(ctx, key)()
		if condition == nil {
			return ""
		}

		return condition.Reason
	}
}

var _ = Describe("WAFPolicy Controller", func() {
	ctx := context.Background()

	Context("when targetRef does not resolve", func() {
		const resourceName = "target-not-found"

		key := types.NamespacedName{Name: resourceName, Namespace: "default"}

		BeforeEach(func() {
			policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      "does-not-exist",
				Namespace: "default",
			})
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("sets Accepted=False/TargetNotFound", func() {
			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionFalse))
			Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonTargetNotFound))
		})
	})

	Context("when targetRef resolves to an existing Gateway", func() {
		const (
			gatewayName   = "accepted-gw"
			resourceName  = "accepted-policy"
			namespaceName = "default"
		)

		key := types.NamespacedName{Name: resourceName, Namespace: namespaceName}

		BeforeEach(func() {
			gw := newTestGateway(namespaceName, gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: gatewayv1.Namespace(namespaceName),
			})
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("sets Accepted=True/Accepted and Programmed=False/Pending, with ObservedGeneration kept current", func() {
			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))

			policy := fetchPolicy(ctx, key)()

			accepted := acceptedCondition(policy)
			Expect(accepted.Reason).To(Equal(gwpv1alpha1.ConditionReasonAccepted))
			Expect(accepted.ObservedGeneration).To(Equal(policy.Generation))

			programmed := programmedCondition(policy)
			Expect(programmed).NotTo(BeNil())
			Expect(programmed.Status).To(Equal(metav1.ConditionFalse))
			Expect(programmed.Reason).To(Equal(gwpv1alpha1.ConditionReasonPending))
			Expect(programmed.ObservedGeneration).To(Equal(policy.Generation))

			By("bumping the policy's generation")
			policy.Spec.ParanoiaLevel = 2
			Expect(k8sClient.Update(ctx, policy)).To(Succeed())

			Eventually(func() int64 {
				updated := fetchPolicy(ctx, key)()
				if updated == nil {
					return -1
				}

				condition := acceptedCondition(updated)
				if condition == nil {
					return -1
				}

				return condition.ObservedGeneration
			}).Should(Equal(policy.Generation))
		})
	})

	Context("when targetRef targets an HTTPRoute", func() {
		const namespaceName = "default"

		Context("and the HTTPRoute exists", func() {
			const (
				routeName    = "accepted-route"
				resourceName = "accepted-route-policy"
			)

			key := types.NamespacedName{Name: resourceName, Namespace: namespaceName}

			BeforeEach(func() {
				route := newTestHTTPRoute(routeName)
				Expect(k8sClient.Create(ctx, route)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, route)).To(Succeed()) })

				policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
					Group:     gatewayv1.GroupName,
					Kind:      "HTTPRoute",
					Name:      gatewayv1.ObjectName(routeName),
					Namespace: gatewayv1.Namespace(namespaceName),
				})
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
			})

			It("sets Accepted=True/Accepted", func() {
				Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))
				Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))
			})
		})

		Context("and the HTTPRoute does not exist", func() {
			const resourceName = "route-not-found-policy"

			key := types.NamespacedName{Name: resourceName, Namespace: namespaceName}

			BeforeEach(func() {
				policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
					Group:     gatewayv1.GroupName,
					Kind:      "HTTPRoute",
					Name:      "does-not-exist",
					Namespace: gatewayv1.Namespace(namespaceName),
				})
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
			})

			It("sets Accepted=False/TargetNotFound", func() {
				Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionFalse))
				Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonTargetNotFound))
			})
		})
	})

	Context("when targetRef sets sectionName", func() {
		const namespaceName = "default"

		Context("and it names an existing Gateway listener", func() {
			const (
				gatewayName  = "section-gw"
				resourceName = "section-gw-policy"
			)

			key := types.NamespacedName{Name: resourceName, Namespace: namespaceName}

			BeforeEach(func() {
				gw := newTestGateway(namespaceName, gatewayName,
					gatewayv1.Listener{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					gatewayv1.Listener{Name: "admin", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
				)
				Expect(k8sClient.Create(ctx, gw)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

				policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
					Group:       gatewayv1.GroupName,
					Kind:        "Gateway",
					Name:        gatewayv1.ObjectName(gatewayName),
					Namespace:   gatewayv1.Namespace(namespaceName),
					SectionName: sectionName("admin"),
				})
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
			})

			It("sets Accepted=True/Accepted", func() {
				Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))
				Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))
			})
		})

		Context("and it names a Gateway listener that does not exist", func() {
			const (
				gatewayName  = "section-missing-gw"
				resourceName = "section-missing-gw-policy"
			)

			key := types.NamespacedName{Name: resourceName, Namespace: namespaceName}

			BeforeEach(func() {
				gw := newTestGateway(namespaceName, gatewayName)
				Expect(k8sClient.Create(ctx, gw)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

				policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
					Group:       gatewayv1.GroupName,
					Kind:        "Gateway",
					Name:        gatewayv1.ObjectName(gatewayName),
					Namespace:   gatewayv1.Namespace(namespaceName),
					SectionName: sectionName("does-not-exist"),
				})
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
			})

			It("sets Accepted=False/TargetNotFound", func() {
				Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionFalse))
				Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonTargetNotFound))
			})
		})

		Context("and it names an existing HTTPRoute rule", func() {
			const (
				routeName    = "section-route"
				resourceName = "section-route-policy"
			)

			key := types.NamespacedName{Name: resourceName, Namespace: namespaceName}

			BeforeEach(func() {
				route := newTestHTTPRoute(routeName,
					gatewayv1.HTTPRouteRule{Name: sectionName("admin")},
				)
				Expect(k8sClient.Create(ctx, route)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, route)).To(Succeed()) })

				policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
					Group:       gatewayv1.GroupName,
					Kind:        "HTTPRoute",
					Name:        gatewayv1.ObjectName(routeName),
					Namespace:   gatewayv1.Namespace(namespaceName),
					SectionName: sectionName("admin"),
				})
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
			})

			It("sets Accepted=True/Accepted", func() {
				Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))
				Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))
			})
		})

		Context("and it names an HTTPRoute rule that does not exist", func() {
			const (
				routeName    = "section-missing-route"
				resourceName = "section-missing-route-policy"
			)

			key := types.NamespacedName{Name: resourceName, Namespace: namespaceName}

			BeforeEach(func() {
				route := newTestHTTPRoute(routeName)
				Expect(k8sClient.Create(ctx, route)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, route)).To(Succeed()) })

				policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
					Group:       gatewayv1.GroupName,
					Kind:        "HTTPRoute",
					Name:        gatewayv1.ObjectName(routeName),
					Namespace:   gatewayv1.Namespace(namespaceName),
					SectionName: sectionName("does-not-exist"),
				})
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())
				DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
			})

			It("sets Accepted=False/TargetNotFound", func() {
				Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionFalse))
				Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonTargetNotFound))
			})
		})
	})

	Context("when the WAFPolicy and its target live in different namespaces", func() {
		const (
			policyNamespace = "default"
			targetNamespace = "waf-target-ns"
			gatewayName     = "cross-ns-gw"
			resourceName    = "cross-ns-policy"
		)

		key := types.NamespacedName{Name: resourceName, Namespace: policyNamespace}

		BeforeEach(func() {
			Expect(ensureNamespace(ctx, targetNamespace)).To(Succeed())

			gw := newTestGateway(targetNamespace, gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			policy := newTestWAFPolicyInNamespace(policyNamespace, resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: gatewayv1.Namespace(targetNamespace),
			})
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("resolves the cross-namespace targetRef and sets Accepted=True/Accepted", func() {
			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))
			Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))
		})
	})

	Context("when customRulesRefs references a missing WAFRuleSet", func() {
		const (
			gatewayName  = "invalid-gw"
			resourceName = "invalid-policy"
		)

		key := types.NamespacedName{Name: resourceName, Namespace: "default"}

		BeforeEach(func() {
			gw := newTestGateway("default", gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			})
			policy.Spec.CustomRulesRefs = []gwpv1alpha1.LocalRuleSetReference{
				{Kind: "WAFRuleSet", Name: "does-not-exist"},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("sets Accepted=False/Invalid", func() {
			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionFalse))
			Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonInvalid))
		})
	})

	Context("when customRulesRefs references an existing WAFRuleSet", func() {
		const (
			gatewayName  = "valid-refs-gw"
			ruleSetName  = "valid-custom-rules"
			resourceName = "valid-refs-policy"
		)

		key := types.NamespacedName{Name: resourceName, Namespace: "default"}

		BeforeEach(func() {
			gw := newTestGateway("default", gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			ruleSet := newTestWAFRuleSet("default", ruleSetName)
			Expect(k8sClient.Create(ctx, ruleSet)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, ruleSet)).To(Succeed()) })

			policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			})
			policy.Spec.CustomRulesRefs = []gwpv1alpha1.LocalRuleSetReference{
				{Kind: "WAFRuleSet", Name: ruleSetName},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("sets Accepted=True/Accepted", func() {
			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))
			Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))
		})
	})

	Context("when the target Gateway is created after the WAFPolicy", func() {
		const (
			gatewayName  = "late-gw"
			resourceName = "late-gw-policy"
		)

		key := types.NamespacedName{Name: resourceName, Namespace: "default"}

		BeforeEach(func() {
			policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			})
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("flips Accepted=False/TargetNotFound to Accepted=True/Accepted once the Gateway is created", func() {
			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionFalse))
			Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonTargetNotFound))

			gw := newTestGateway("default", gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))
			Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))
		})
	})

	Context("when the target Gateway is deleted after acceptance", func() {
		const (
			gatewayName  = "removed-gw"
			resourceName = "removed-gw-policy"
		)

		key := types.NamespacedName{Name: resourceName, Namespace: "default"}

		BeforeEach(func() {
			gw := newTestGateway("default", gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())

			policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			})
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("flips Accepted=True/Accepted to Accepted=False/TargetNotFound once the Gateway is deleted", func() {
			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))

			gw := &gatewayv1.Gateway{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: gatewayName, Namespace: "default"}, gw)).To(Succeed())
			Expect(k8sClient.Delete(ctx, gw)).To(Succeed())

			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionFalse))
			Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonTargetNotFound))
		})
	})

	Context("when a missing WAFRuleSet is created after rejection", func() {
		const (
			gatewayName  = "late-refs-gw"
			ruleSetName  = "late-custom-rules"
			resourceName = "late-refs-policy"
		)

		key := types.NamespacedName{Name: resourceName, Namespace: "default"}

		BeforeEach(func() {
			gw := newTestGateway("default", gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			})
			policy.Spec.CustomRulesRefs = []gwpv1alpha1.LocalRuleSetReference{
				{Kind: "WAFRuleSet", Name: ruleSetName},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("flips Accepted=False/Invalid to Accepted=True/Accepted once the WAFRuleSet is created", func() {
			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionFalse))
			Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonInvalid))

			ruleSet := newTestWAFRuleSet("default", ruleSetName)
			Expect(k8sClient.Create(ctx, ruleSet)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, ruleSet)).To(Succeed()) })

			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))
			Expect(acceptedReason(ctx, key)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))
		})
	})

	Context("when a Gateway-level and a Route-level WAFPolicy target the same Gateway", func() {
		const (
			gatewayName       = "override-gw"
			routeName         = "override-route"
			gatewayPolicyName = "override-gw-policy"
			routePolicyName   = "override-route-policy"
		)

		gatewayPolicyKey := types.NamespacedName{Name: gatewayPolicyName, Namespace: "default"}
		routePolicyKey := types.NamespacedName{Name: routePolicyName, Namespace: "default"}

		BeforeEach(func() {
			gw := newTestGateway("default", gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			route := newTestHTTPRoute(routeName)
			Expect(k8sClient.Create(ctx, route)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, route)).To(Succeed()) })

			gatewayPolicy := newTestWAFPolicy(gatewayPolicyName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			})
			Expect(k8sClient.Create(ctx, gatewayPolicy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gatewayPolicy)).To(Succeed()) })

			routePolicy := newTestWAFPolicy(routePolicyName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "HTTPRoute",
				Name:      gatewayv1.ObjectName(routeName),
				Namespace: "default",
			})
			Expect(k8sClient.Create(ctx, routePolicy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, routePolicy)).To(Succeed()) })
		})

		It("accepts both - this is most-specific-wins, not a conflict", func() {
			Eventually(acceptedStatus(ctx, gatewayPolicyKey)).Should(Equal(metav1.ConditionTrue))
			Expect(acceptedReason(ctx, gatewayPolicyKey)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))

			Eventually(acceptedStatus(ctx, routePolicyKey)).Should(Equal(metav1.ConditionTrue))
			Expect(acceptedReason(ctx, routePolicyKey)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))
		})
	})

	Context("when two WAFPolicy target the same Gateway with different sectionNames", func() {
		const (
			gatewayName     = "multi-section-gw"
			httpPolicyName  = "multi-section-http-policy"
			adminPolicyName = "multi-section-admin-policy"
		)

		httpPolicyKey := types.NamespacedName{Name: httpPolicyName, Namespace: "default"}
		adminPolicyKey := types.NamespacedName{Name: adminPolicyName, Namespace: "default"}

		BeforeEach(func() {
			gw := newTestGateway("default", gatewayName,
				gatewayv1.Listener{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				gatewayv1.Listener{Name: "admin", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
			)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			httpPolicy := newTestWAFPolicy(httpPolicyName, gwpv1alpha1.PolicyTargetReference{
				Group:       gatewayv1.GroupName,
				Kind:        "Gateway",
				Name:        gatewayv1.ObjectName(gatewayName),
				Namespace:   "default",
				SectionName: sectionName("http"),
			})
			Expect(k8sClient.Create(ctx, httpPolicy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, httpPolicy)).To(Succeed()) })

			adminPolicy := newTestWAFPolicy(adminPolicyName, gwpv1alpha1.PolicyTargetReference{
				Group:       gatewayv1.GroupName,
				Kind:        "Gateway",
				Name:        gatewayv1.ObjectName(gatewayName),
				Namespace:   "default",
				SectionName: sectionName("admin"),
			})
			Expect(k8sClient.Create(ctx, adminPolicy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, adminPolicy)).To(Succeed()) })
		})

		It("accepts both - they target different attachment points", func() {
			Eventually(acceptedStatus(ctx, httpPolicyKey)).Should(Equal(metav1.ConditionTrue))
			Expect(acceptedReason(ctx, httpPolicyKey)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))

			Eventually(acceptedStatus(ctx, adminPolicyKey)).Should(Equal(metav1.ConditionTrue))
			Expect(acceptedReason(ctx, adminPolicyKey)()).To(Equal(gwpv1alpha1.ConditionReasonAccepted))
		})
	})

	Context("when two WAFPolicy objects target the same Gateway", func() {
		const gatewayName = "conflict-gw"

		var (
			olderKey, newerKey types.NamespacedName
		)

		BeforeEach(func() {
			gw := newTestGateway("default", gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			targetRef := gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			}

			older := newTestWAFPolicy("conflict-a-first", targetRef)
			Expect(k8sClient.Create(ctx, older)).To(Succeed())
			olderKey = types.NamespacedName{Name: older.Name, Namespace: older.Namespace}
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, older)
			})

			// Both objects are created in quick succession, and
			// CreationTimestamp only has second-level resolution, so they
			// may well tie: rely on the deterministic namespace/name
			// tiebreak (see isOlder in wafpolicy_conflicts.go) rather than
			// wall-clock ordering, hence the "a-first"/"b-second" names.
			newer := newTestWAFPolicy("conflict-b-second", targetRef)
			Expect(k8sClient.Create(ctx, newer)).To(Succeed())
			newerKey = types.NamespacedName{Name: newer.Name, Namespace: newer.Namespace}
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, newer)
			})
		})

		It("accepts the older policy and marks the newer one Conflicted", func() {
			Eventually(acceptedStatus(ctx, olderKey)).Should(Equal(metav1.ConditionTrue))
			Eventually(acceptedReason(ctx, newerKey)).Should(Equal(gwpv1alpha1.ConditionReasonConflicted))

			By("deleting the winning policy so the loser becomes Accepted")
			winner := fetchPolicy(ctx, olderKey)()
			Expect(k8sClient.Delete(ctx, winner)).To(Succeed())

			Eventually(acceptedStatus(ctx, newerKey)).Should(Equal(metav1.ConditionTrue))
		})
	})

	Context("when two WAFPolicy objects target the same HTTPRoute", func() {
		const routeName = "conflict-route"

		var (
			olderKey, newerKey types.NamespacedName
		)

		BeforeEach(func() {
			route := newTestHTTPRoute(routeName)
			Expect(k8sClient.Create(ctx, route)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, route)).To(Succeed()) })

			targetRef := gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "HTTPRoute",
				Name:      gatewayv1.ObjectName(routeName),
				Namespace: "default",
			}

			// Same tiebreak-friendly naming as the Gateway conflict test
			// above (see the comment there).
			older := newTestWAFPolicy("route-conflict-a-first", targetRef)
			Expect(k8sClient.Create(ctx, older)).To(Succeed())
			olderKey = types.NamespacedName{Name: older.Name, Namespace: older.Namespace}
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, older)
			})

			newer := newTestWAFPolicy("route-conflict-b-second", targetRef)
			Expect(k8sClient.Create(ctx, newer)).To(Succeed())
			newerKey = types.NamespacedName{Name: newer.Name, Namespace: newer.Namespace}
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, newer)
			})
		})

		It("accepts the older policy and marks the newer one Conflicted", func() {
			Eventually(acceptedStatus(ctx, olderKey)).Should(Equal(metav1.ConditionTrue))
			Eventually(acceptedReason(ctx, newerKey)).Should(Equal(gwpv1alpha1.ConditionReasonConflicted))

			By("deleting the winning policy so the loser becomes Accepted")
			winner := fetchPolicy(ctx, olderKey)()
			Expect(k8sClient.Delete(ctx, winner)).To(Succeed())

			Eventually(acceptedStatus(ctx, newerKey)).Should(Equal(metav1.ConditionTrue))
		})
	})
})
