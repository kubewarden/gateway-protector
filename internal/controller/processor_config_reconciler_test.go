package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

// publishedConfig returns the most recently published processor config,
// via the recordingPublisher wired into ProcessorConfigReconciler for this
// suite (see suite_test.go) - not by reading the ConfigMap, so specs stay
// agnostic to the publishing transport (ConfigMap today, possibly a future
// gRPC stream). It is meant to be called from inside an Eventually/inline
// assertion, not used to poll for a first publish (the priming run - see
// ProcessorConfigReconciler's SetupWithManager - guarantees one exists
// very early).
func publishedConfig() *procconfig.Config {
	return publishedConfigs.lastConfig()
}

// findRoute returns the first route in cfg matching host+pathPrefix
// exactly, so tests can assert on their own policy's contribution to the
// processor config without being sensitive to what other, unrelated
// WAFPolicy objects (from other specs, running against the same shared
// manager/ConfigMap) may currently also be contributing.
func findRoute(cfg *procconfig.Config, host, pathPrefix string) *procconfig.Route {
	for i := range cfg.Routes {
		if cfg.Routes[i].Host == host && cfg.Routes[i].PathPrefix == pathPrefix {
			return &cfg.Routes[i]
		}
	}

	return nil
}

var _ = Describe("ProcessorConfigReconciler", func() {
	ctx := context.Background()

	Context("when a WAFPolicy is Accepted", func() {
		const (
			gatewayName  = "procconfig-gw"
			routeName    = "procconfig-route"
			resourceName = "procconfig-policy"
		)

		key := types.NamespacedName{Name: resourceName, Namespace: "default"}

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
					Hostnames: []gatewayv1.Hostname{"procconfig.example.com"},
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
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("publishes an engine and route entry, and sets Programmed=True/Programmed", func() {
			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))

			Eventually(func() (*metav1.Condition, error) {
				updated, err := fetchPolicy(ctx, key)()
				if err != nil || updated == nil {
					return nil, err
				}

				return programmedCondition(updated), nil
			}).Should(And(
				Not(BeNil()),
				HaveField("Status", metav1.ConditionTrue),
				HaveField("Reason", gwpv1alpha1.ConditionReasonProgrammed),
			))

			var route *procconfig.Route
			Eventually(func() *procconfig.Route {
				route = findRoute(publishedConfig(), "procconfig.example.com", "/")
				return route
			}).ShouldNot(BeNil())

			Expect(route.WAF).NotTo(BeNil())

			cfg := publishedConfig()
			directives, found := cfg.Directives[route.WAF.EngineKey]
			Expect(found).To(BeTrue(), "the route's engine key must have a matching directives entry")
			Expect(directives).To(ContainSubstring("SecRuleEngine On"))
		})
	})

	Context("when a WAFPolicy references a WAFRuleSet with an invalid directive", func() {
		const (
			gatewayName  = "procconfig-invalid-gw"
			routeName    = "procconfig-invalid-route"
			ruleSetName  = "procconfig-invalid-ruleset"
			resourceName = "procconfig-invalid-policy"
		)

		key := types.NamespacedName{Name: resourceName, Namespace: "default"}

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
					Hostnames: []gatewayv1.Hostname{"procconfig-invalid.example.com"},
					Rules:     []gatewayv1.HTTPRouteRule{{}},
				},
			}
			Expect(k8sClient.Create(ctx, route)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, route)).To(Succeed()) })

			ruleSet := &gwpv1alpha1.WAFRuleSet{
				ObjectMeta: metav1.ObjectMeta{Name: ruleSetName, Namespace: "default"},
				Spec: gwpv1alpha1.WAFRuleSetSpec{
					Rules: []gwpv1alpha1.WAFCustomRule{
						{ID: 1, Directive: "ThisIsNotAValidSecRuleDirective"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, ruleSet)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, ruleSet)).To(Succeed()) })

			policy := newTestWAFPolicy(resourceName, gwpv1alpha1.PolicyTargetReference{
				Group:     gatewayv1.GroupName,
				Kind:      "Gateway",
				Name:      gatewayv1.ObjectName(gatewayName),
				Namespace: "default",
			})
			policy.Spec.CustomRulesRefs = []gwpv1alpha1.LocalRuleSetReference{
				{Name: ruleSetName},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(ctx, policy)).To(Succeed()) })
		})

		It("sets Programmed=False/CompileFailed and excludes the policy from the published config", func() {
			Eventually(acceptedStatus(ctx, key)).Should(Equal(metav1.ConditionTrue))

			Eventually(func() (*metav1.Condition, error) {
				updated, err := fetchPolicy(ctx, key)()
				if err != nil || updated == nil {
					return nil, err
				}

				return programmedCondition(updated), nil
			}).Should(And(
				Not(BeNil()),
				HaveField("Status", metav1.ConditionFalse),
				HaveField("Reason", gwpv1alpha1.ConditionReasonCompileFailed),
			))

			// Reconcile publishes the config before updating Programmed (see
			// its doc comment), so the CompileFailed condition being visible
			// already guarantees the corresponding config was recorded - a
			// plain Expect, not another Eventually, is enough here.
			cfg := publishedConfig()
			route := findRoute(cfg, "procconfig-invalid.example.com", "/")
			Expect(route).To(BeNil(), "a policy that failed to compile must not cover any route in the published config")
		})
	})

	// This is the only spec in this file allowed to know the processor
	// config is currently published as a ConfigMap - every other spec
	// asserts through publishedConfig() (see suite_test.go's
	// recordingPublisher), which stays agnostic to the transport. If the
	// transport ever changes (e.g. to a future gRPC config stream),
	// replace this spec, not the others.
	Context("the published config's transport", func() {
		It("round-trips through the ConfigMap ConfigMapPublisher writes", func() {
			Eventually(func() bool {
				want := publishedConfig()
				if want == nil {
					return false
				}

				// Comparing the marshaled YAML text (what ConfigMapPublisher
				// itself writes) rather than unmarshaling the ConfigMap back
				// into a procconfig.Config and comparing structs: a nil slice
				// (e.g. Routes with no entries) round-trips through YAML as a
				// non-nil empty slice, which would make a struct-level
				// comparison spuriously fail.
				wantYAML, err := yaml.Marshal(want)
				if err != nil {
					return false
				}

				cm := &corev1.ConfigMap{}
				key := types.NamespacedName{Name: ProcessorConfigMapName, Namespace: processorConfigMapNamespace}
				if err := k8sClient.Get(ctx, key, cm); err != nil {
					return false
				}

				return cm.Data["config.yaml"] == string(wantYAML)
			}).Should(BeTrue())
		})
	})
})
