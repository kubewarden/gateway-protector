package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/kubewarden/gateway-protector/internal/certs"
)

// newCertReconcilerTestNamespace creates a fresh Namespace for a cert
// reconciler test Context to create its CA/leaf Secrets in: the
// reconciler uses fixed Secret/ConfigMap names (see internal/certs), so
// each Ordered Context needs its own namespace to avoid clashing with the
// others.
func newCertReconcilerTestNamespace(ctx context.Context, name string) {
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
}

func createCASecret(ctx context.Context, namespace string, caCert, caPrivateKey []byte, oldCACert []byte) {
	data := map[string][]byte{
		certs.CertKey:       caCert,
		certs.PrivateKeyKey: caPrivateKey,
	}
	if oldCACert != nil {
		data[certs.OldCACertKey] = oldCACert
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: certs.CASecretName},
		Type:       corev1.SecretTypeTLS,
		Data:       data,
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
}

func createLeafSecret(ctx context.Context, namespace, name string, cert, privateKey, caBundle []byte) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			certs.CertKey:       cert,
			certs.PrivateKeyKey: privateKey,
			certs.CABundleKey:   caBundle,
		},
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
}

func createCABundleConfigMap(ctx context.Context, namespace string, caBundle []byte) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: certs.CABundleConfigMapName},
		Data:       map[string]string{certs.CABundleKey: string(caBundle)},
	}
	Expect(k8sClient.Create(ctx, configMap)).To(Succeed())
}

// leafCerts holds the cert/key pairs createLeafSecrets generated, so a
// test can assert a particular leaf was (or wasn't) actually regenerated
// by comparing against what it started with.
type leafCerts struct {
	controllerCert, controllerKey                 []byte
	processorClientCert, processorClientKey       []byte
	processorServerCert, processorServerKey       []byte
	agentgatewayClientCert, agentgatewayClientKey []byte
}

// createLeafSecrets creates every leaf Secret CertReconciler expects to
// find in namespace (controller server, processor client, processor
// server, agentgateway client), all signed by caCert/caPrivateKey with
// the given validity bounds and initial CA bundle.
func createLeafSecrets(namespace string, caCert, caPrivateKey []byte, notBefore, notAfter time.Time, caBundle []byte) leafCerts {
	ctx := context.Background()
	var leafs leafCerts

	controllerDNSName := certs.ControllerServerDNSName + "." + namespace + ".svc"
	var err error
	leafs.controllerCert, leafs.controllerKey, err = certs.GenerateCert(caCert, caPrivateKey, notBefore, notAfter, controllerDNSName)
	Expect(err).NotTo(HaveOccurred())
	createLeafSecret(ctx, namespace, certs.ControllerCertSecretName, leafs.controllerCert, leafs.controllerKey, caBundle)

	leafs.processorClientCert, leafs.processorClientKey, err = certs.GenerateCert(caCert, caPrivateKey, notBefore, notAfter, certs.ProcessorClientCommonName)
	Expect(err).NotTo(HaveOccurred())
	createLeafSecret(ctx, namespace, certs.ProcessorClientCertSecretName, leafs.processorClientCert, leafs.processorClientKey, caBundle)

	processorServerDNSName := certs.DNSName(certs.ProcessorServerServiceName, namespace)
	leafs.processorServerCert, leafs.processorServerKey, err = certs.GenerateCert(caCert, caPrivateKey, notBefore, notAfter, processorServerDNSName)
	Expect(err).NotTo(HaveOccurred())
	createLeafSecret(ctx, namespace, certs.ProcessorServerCertSecretName, leafs.processorServerCert, leafs.processorServerKey, caBundle)

	leafs.agentgatewayClientCert, leafs.agentgatewayClientKey, err = certs.GenerateCert(caCert, caPrivateKey, notBefore, notAfter, certs.AgentgatewayClientCommonName)
	Expect(err).NotTo(HaveOccurred())
	createLeafSecret(ctx, namespace, certs.AgentgatewayClientCertSecretName, leafs.agentgatewayClientCert, leafs.agentgatewayClientKey, caBundle)

	return leafs
}

var _ = Describe("Cert reconciler", func() {
	ctx := context.Background()

	Context("Leaf certificate rotation", Ordered, func() {
		const namespace = "cert-reconciler-leaf-rotation"

		BeforeAll(func() {
			newCertReconcilerTestNamespace(ctx, namespace)

			caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(certs.CAExpiration))
			Expect(err).NotTo(HaveOccurred())
			createCASecret(ctx, namespace, caCert, caPrivateKey, nil)
			createCABundleConfigMap(ctx, namespace, caCert)

			// Every leaf is already within the rotation lookahead, so
			// reconcile must regenerate all four of them.
			createLeafSecrets(namespace, caCert, caPrivateKey,
				time.Now().Add(-certs.LeafExpiration), time.Now().Add(certs.RotationLookahead), caCert)

			reconciler := CertReconciler{Client: k8sClient, Namespace: namespace}
			Expect(reconciler.reconcile(ctx)).To(Succeed())
		})

		It("rotates the controller server certificate", func() {
			caSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CASecretName, Namespace: namespace}, caSecret)).To(Succeed())
			caCert, _, err := certs.ExtractCA(caSecret)
			Expect(err).NotTo(HaveOccurred())
			pool, err := certs.NewCertPool(caCert)
			Expect(err).NotTo(HaveOccurred())

			leafSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.ControllerCertSecretName, Namespace: namespace}, leafSecret)).To(Succeed())

			dnsName := certs.ControllerServerDNSName + "." + namespace + ".svc"
			err = certs.VerifyCert(leafSecret.Data[certs.CertKey], leafSecret.Data[certs.PrivateKeyKey], pool, dnsName, time.Now())
			Expect(err).NotTo(HaveOccurred())
		})

		It("rotates the processor client certificate", func() {
			caSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CASecretName, Namespace: namespace}, caSecret)).To(Succeed())
			caCert, _, err := certs.ExtractCA(caSecret)
			Expect(err).NotTo(HaveOccurred())
			pool, err := certs.NewCertPool(caCert)
			Expect(err).NotTo(HaveOccurred())

			leafSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.ProcessorClientCertSecretName, Namespace: namespace}, leafSecret)).To(Succeed())

			err = certs.VerifyCert(leafSecret.Data[certs.CertKey], leafSecret.Data[certs.PrivateKeyKey], pool, certs.ProcessorClientCommonName, time.Now())
			Expect(err).NotTo(HaveOccurred())
		})

		It("rotates the processor's ext_proc server certificate", func() {
			caSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CASecretName, Namespace: namespace}, caSecret)).To(Succeed())
			caCert, _, err := certs.ExtractCA(caSecret)
			Expect(err).NotTo(HaveOccurred())
			pool, err := certs.NewCertPool(caCert)
			Expect(err).NotTo(HaveOccurred())

			leafSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.ProcessorServerCertSecretName, Namespace: namespace}, leafSecret)).To(Succeed())

			dnsName := certs.DNSName(certs.ProcessorServerServiceName, namespace)
			err = certs.VerifyCert(leafSecret.Data[certs.CertKey], leafSecret.Data[certs.PrivateKeyKey], pool, dnsName, time.Now())
			Expect(err).NotTo(HaveOccurred())
		})

		It("rotates the agentgateway client certificate", func() {
			caSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CASecretName, Namespace: namespace}, caSecret)).To(Succeed())
			caCert, _, err := certs.ExtractCA(caSecret)
			Expect(err).NotTo(HaveOccurred())
			pool, err := certs.NewCertPool(caCert)
			Expect(err).NotTo(HaveOccurred())

			leafSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.AgentgatewayClientCertSecretName, Namespace: namespace}, leafSecret)).To(Succeed())

			err = certs.VerifyCert(leafSecret.Data[certs.CertKey], leafSecret.Data[certs.PrivateKeyKey], pool, certs.AgentgatewayClientCommonName, time.Now())
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("CA rotation", Ordered, func() {
		const namespace = "cert-reconciler-ca-rotation"

		var controllerCert, controllerKey []byte

		BeforeAll(func() {
			newCertReconcilerTestNamespace(ctx, namespace)

			caCert, caPrivateKey, err := certs.GenerateCA(time.Now().Add(-certs.CAExpiration), time.Now().Add(certs.RotationLookahead))
			Expect(err).NotTo(HaveOccurred())
			createCASecret(ctx, namespace, caCert, caPrivateKey, nil)
			createCABundleConfigMap(ctx, namespace, caCert)

			leafs := createLeafSecrets(namespace, caCert, caPrivateKey, time.Now(), time.Now().Add(certs.LeafExpiration), caCert)
			controllerCert, controllerKey = leafs.controllerCert, leafs.controllerKey

			reconciler := CertReconciler{Client: k8sClient, Namespace: namespace}
			Expect(reconciler.reconcile(ctx)).To(Succeed())
		})

		It("rotates the CA certificate and stashes the previous one", func() {
			caSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CASecretName, Namespace: namespace}, caSecret)).To(Succeed())

			caCert, caPrivateKey, err := certs.ExtractCA(caSecret)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs.VerifyCA(caCert, caPrivateKey, time.Now())).To(Succeed())
			Expect(caSecret.Data).To(HaveKey(certs.OldCACertKey))
		})

		It("updates the CA bundle configmap", func() {
			caSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CASecretName, Namespace: namespace}, caSecret)).To(Succeed())
			expectedBundle := string(append(append([]byte{}, caSecret.Data[certs.CertKey]...), caSecret.Data[certs.OldCACertKey]...))

			configMap := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CABundleConfigMapName, Namespace: namespace}, configMap)).To(Succeed())
			Expect(configMap.Data[certs.CABundleKey]).To(Equal(expectedBundle))
		})

		It("rotates every leaf certificate against the new CA and refreshes their CA bundle", func() {
			caSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CASecretName, Namespace: namespace}, caSecret)).To(Succeed())
			expectedBundle := append(append([]byte{}, caSecret.Data[certs.CertKey]...), caSecret.Data[certs.OldCACertKey]...)

			pool, err := certs.NewCertPool(expectedBundle)
			Expect(err).NotTo(HaveOccurred())

			controllerSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.ControllerCertSecretName, Namespace: namespace}, controllerSecret)).To(Succeed())
			Expect(controllerSecret.Data[certs.CABundleKey]).To(Equal(expectedBundle))
			dnsName := certs.ControllerServerDNSName + "." + namespace + ".svc"
			Expect(certs.VerifyCert(controllerSecret.Data[certs.CertKey], controllerSecret.Data[certs.PrivateKeyKey], pool, dnsName, time.Now())).To(Succeed())
			// The certificate must have actually been regenerated (signed by the new CA), not merely left in place.
			Expect(controllerSecret.Data[certs.CertKey]).NotTo(Equal(controllerCert))
			Expect(controllerSecret.Data[certs.PrivateKeyKey]).NotTo(Equal(controllerKey))

			processorSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.ProcessorClientCertSecretName, Namespace: namespace}, processorSecret)).To(Succeed())
			Expect(processorSecret.Data[certs.CABundleKey]).To(Equal(expectedBundle))
			Expect(certs.VerifyCert(processorSecret.Data[certs.CertKey], processorSecret.Data[certs.PrivateKeyKey], pool, certs.ProcessorClientCommonName, time.Now())).To(Succeed())

			processorServerSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.ProcessorServerCertSecretName, Namespace: namespace}, processorServerSecret)).To(Succeed())
			Expect(processorServerSecret.Data[certs.CABundleKey]).To(Equal(expectedBundle))
			processorServerDNSName := certs.DNSName(certs.ProcessorServerServiceName, namespace)
			Expect(certs.VerifyCert(processorServerSecret.Data[certs.CertKey], processorServerSecret.Data[certs.PrivateKeyKey], pool, processorServerDNSName, time.Now())).To(Succeed())

			agentgatewayClientSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.AgentgatewayClientCertSecretName, Namespace: namespace}, agentgatewayClientSecret)).To(Succeed())
			Expect(agentgatewayClientSecret.Data[certs.CABundleKey]).To(Equal(expectedBundle))
			Expect(certs.VerifyCert(agentgatewayClientSecret.Data[certs.CertKey], agentgatewayClientSecret.Data[certs.PrivateKeyKey], pool, certs.AgentgatewayClientCommonName, time.Now())).To(Succeed())
		})
	})

	Context("Old CA cleanup", Ordered, func() {
		const namespace = "cert-reconciler-old-ca-cleanup"

		BeforeAll(func() {
			newCertReconcilerTestNamespace(ctx, namespace)

			caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(certs.CAExpiration))
			Expect(err).NotTo(HaveOccurred())
			oldCACert, _, err := certs.GenerateCA(time.Now().Add(-certs.CAExpiration), time.Now().Add(-24*time.Hour))
			Expect(err).NotTo(HaveOccurred())
			createCASecret(ctx, namespace, caCert, caPrivateKey, oldCACert)

			bundle := append(append([]byte{}, caCert...), oldCACert...)
			createCABundleConfigMap(ctx, namespace, bundle)
			createLeafSecrets(namespace, caCert, caPrivateKey, time.Now(), time.Now().Add(certs.LeafExpiration), bundle)

			reconciler := CertReconciler{Client: k8sClient, Namespace: namespace}
			Expect(reconciler.reconcile(ctx)).To(Succeed())
		})

		It("removes the expired old CA certificate and shrinks the leaf CA bundles back down", func() {
			caSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CASecretName, Namespace: namespace}, caSecret)).To(Succeed())
			Expect(caSecret.Data).NotTo(HaveKey(certs.OldCACertKey))

			controllerSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.ControllerCertSecretName, Namespace: namespace}, controllerSecret)).To(Succeed())
			Expect(controllerSecret.Data[certs.CABundleKey]).To(Equal(caSecret.Data[certs.CertKey]))
		})

		It("shrinks the CA bundle configmap back down too", func() {
			caSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CASecretName, Namespace: namespace}, caSecret)).To(Succeed())

			configMap := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: certs.CABundleConfigMapName, Namespace: namespace}, configMap)).To(Succeed())
			Expect(configMap.Data[certs.CABundleKey]).To(Equal(string(caSecret.Data[certs.CertKey])))
		})
	})
})
