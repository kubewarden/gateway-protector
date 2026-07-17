package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gatewayprotectorkubewardeniov1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
)

var _ = Describe("WAFPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const (
			resourceName      = "test-resource"
			resourceNamespace = "default"
		)

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: resourceNamespace,
		}
		wafpolicy := &gatewayprotectorkubewardeniov1alpha1.WAFPolicy{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind WAFPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, wafpolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &gatewayprotectorkubewardeniov1alpha1.WAFPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: resourceNamespace,
					},
					Spec: gatewayprotectorkubewardeniov1alpha1.WAFPolicySpec{
						TargetRef: gatewayprotectorkubewardeniov1alpha1.PolicyTargetReference{
							Group:     gatewayv1.GroupName,
							Kind:      "Gateway",
							Name:      "shared-gw",
							Namespace: "infra",
						},
						Engine: gatewayprotectorkubewardeniov1alpha1.WAFEngineSpec{
							Mode:        gatewayprotectorkubewardeniov1alpha1.WAFEngineModeBlocking,
							FailureMode: gatewayprotectorkubewardeniov1alpha1.FailureModeClosed,
						},
						ParanoiaLevel: 1,
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &gatewayprotectorkubewardeniov1alpha1.WAFPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance WAFPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &WAFPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})
})
