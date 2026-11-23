package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
	"github.com/kubewarden/gateway-protector/internal/agentgatewayapi"
)

// fetchWiringPolicy returns a poll function fetching the generated
// AgentgatewayPolicy for the named route (in the "default" namespace, like
// every route these specs create). Like fetchPolicy, a NotFound Get is
// reported as (nil, nil) - a genuine "doesn't exist (yet/anymore)", not an
// error - so both Eventually and a direct Expect on the tuple behave
// correctly whether the spec is waiting for creation or for deletion.
func fetchWiringPolicy(ctx context.Context, routeName string) func() (*agentgatewayapi.AgentgatewayPolicy, error) {
	key := types.NamespacedName{Namespace: "default", Name: wiringPolicyName(routeName)}

	return func() (*agentgatewayapi.AgentgatewayPolicy, error) {
		policy := &agentgatewayapi.AgentgatewayPolicy{}

		err := k8sClient.Get(ctx, key, policy)
		if apierrors.IsNotFound(err) {
			return nil, nil
		}

		if err != nil {
			return nil, err
		}

		return policy, nil
	}
}

var _ = Describe("Gateway wiring (generated AgentgatewayPolicy)", func() {
	ctx := context.Background()

	Context("when a WAFPolicy covers an HTTPRoute", func() {
		const (
			gatewayName  = "wiring-gw"
			routeName    = "wiring-route"
			resourceName = "wiring-policy"
		)

		policyKey := types.NamespacedName{Name: resourceName, Namespace: "default"}

		BeforeEach(func() {
			gw := newTestGateway("default", gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: routeName, Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gatewayName)}},
					},
					Hostnames: []gatewayv1.Hostname{"wiring.example.com"},
					Rules:     []gatewayv1.HTTPRouteRule{{}},
				},
			}
			Expect(k8sClient.Create(ctx, route)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, route)).To(Succeed()) })

			policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			})
			policy.Spec.RequestBody = &gwpv1alpha1.WAFBodyInspectionSpec{Enabled: true}
			policy.Spec.ResponseBody = &gwpv1alpha1.WAFBodyInspectionSpec{Enabled: false}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("generates the AgentgatewayPolicy in the route's namespace, owned by the route", func() {
			Eventually(acceptedStatus(ctx, policyKey)).Should(Equal(metav1.ConditionTrue))

			var wiringPolicy *agentgatewayapi.AgentgatewayPolicy
			Eventually(func() (*agentgatewayapi.AgentgatewayPolicy, error) {
				var err error

				wiringPolicy, err = fetchWiringPolicy(ctx, routeName)()

				return wiringPolicy, err
			}).ShouldNot(BeNil())

			Expect(wiringPolicy.Labels).To(HaveKeyWithValue(wiringManagedLabel, "true"))

			Expect(wiringPolicy.OwnerReferences).To(HaveLen(1))
			Expect(wiringPolicy.OwnerReferences[0].Kind).To(Equal("HTTPRoute"))
			Expect(wiringPolicy.OwnerReferences[0].Name).To(Equal(routeName))

			Expect(wiringPolicy.Spec.TargetRefs).To(HaveLen(1))
			Expect(wiringPolicy.Spec.TargetRefs[0].Kind).To(Equal(gatewayv1.Kind("HTTPRoute")))
			Expect(wiringPolicy.Spec.TargetRefs[0].Name).To(Equal(gatewayv1.ObjectName(routeName)))

			extProc := wiringPolicy.Spec.Traffic.ExtProc
			Expect(extProc).NotTo(BeNil())
			Expect(extProc.BackendRef.Name).To(Equal(gatewayv1.ObjectName(ProcessorServiceName)))
			Expect(*extProc.BackendRef.Namespace).To(Equal(gatewayv1.Namespace(processorNamespace)))
			Expect(*extProc.BackendRef.Port).To(Equal(gatewayv1.PortNumber(ProcessorServicePort)))

			options := extProc.ProcessingOptions
			Expect(options).NotTo(BeNil())
			Expect(*options.RequestBodyMode).To(Equal(agentgatewayapi.BodySendModeFullDuplexStreamed))
			Expect(*options.ResponseBodyMode).To(Equal(agentgatewayapi.BodySendModeNone))

			// The agentgateway CRD accepted the metadataContext together
			// with backendRef and processingOptions, and kept it intact.
			Expect(extProc.MetadataContext).To(Equal(wiringMetadataContext()))
		})

		It("repairs drift on the fields it owns", func() {
			Eventually(fetchWiringPolicy(ctx, routeName)).ShouldNot(BeNil())

			// Simulate a manual edit of a field this controller owns.
			drifted, err := fetchWiringPolicy(ctx, routeName)()
			Expect(err).NotTo(HaveOccurred())
			Expect(drifted).NotTo(BeNil())
			drifted.Spec.Traffic.ExtProc.ProcessingOptions.RequestBodyMode = ptr.To(agentgatewayapi.BodySendModeNone)
			Expect(k8sClient.Update(ctx, drifted)).To(Succeed())

			Eventually(func() (agentgatewayapi.BodySendMode, error) {
				policy, err := fetchWiringPolicy(ctx, routeName)()
				if err != nil || policy == nil || policy.Spec.Traffic == nil || policy.Spec.Traffic.ExtProc == nil ||
					policy.Spec.Traffic.ExtProc.ProcessingOptions == nil ||
					policy.Spec.Traffic.ExtProc.ProcessingOptions.RequestBodyMode == nil {
					return "", err
				}

				return *policy.Spec.Traffic.ExtProc.ProcessingOptions.RequestBodyMode, nil
			}).Should(Equal(agentgatewayapi.BodySendModeFullDuplexStreamed))
		})

		It("garbage-collects the AgentgatewayPolicy when the WAFPolicy is deleted", func() {
			Eventually(fetchWiringPolicy(ctx, routeName)).ShouldNot(BeNil())

			policy, err := fetchPolicy(ctx, policyKey)()
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())

			Eventually(fetchWiringPolicy(ctx, routeName)).Should(BeNil())

			// Recreate so the BeforeEach's DeferCleanup delete still succeeds.
			recreated := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			})
			Expect(k8sClient.Create(ctx, recreated)).To(Succeed())
		})
	})

	Context("when a WAFPolicy's directives fail to compile", func() {
		const (
			gatewayName  = "wiring-broken-gw"
			routeName    = "wiring-broken-route"
			ruleSetName  = "wiring-broken-ruleset"
			resourceName = "wiring-broken-policy"
		)

		policyKey := types.NamespacedName{Name: resourceName, Namespace: "default"}

		BeforeEach(func() {
			gw := newTestGateway("default", gatewayName)
			Expect(k8sClient.Create(ctx, gw)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, gw)).To(Succeed()) })

			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Name: routeName, Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gatewayName)}},
					},
					Rules: []gatewayv1.HTTPRouteRule{{}},
				},
			}
			Expect(k8sClient.Create(ctx, route)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, route)).To(Succeed()) })

			ruleSet := newTestWAFRuleSet(ruleSetName)
			ruleSet.Spec.Rules[0].Directive = "ThisIsNotAValidSecRuleDirective"
			Expect(k8sClient.Create(ctx, ruleSet)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, ruleSet)).To(Succeed()) })

			policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			})
			policy.Spec.CustomRulesRefs = []gwpv1alpha1.LocalRuleSetReference{{Name: ruleSetName}}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("does not wire the route", func() {
			Eventually(func() (*metav1.Condition, error) {
				updated, err := fetchPolicy(ctx, policyKey)()
				if err != nil || updated == nil {
					return nil, err
				}

				return programmedCondition(updated), nil
			}).Should(And(
				Not(BeNil()),
				HaveField("Reason", gwpv1alpha1.ConditionReasonCompileFailed),
			))

			// CompileFailed is set after reconcileWiring ran in the same
			// pass, so the absence check is race-free (see Reconcile).
			Expect(fetchWiringPolicy(ctx, routeName)()).To(BeNil())
		})
	})
})
