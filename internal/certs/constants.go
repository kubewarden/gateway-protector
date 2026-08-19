package certs

import "time"

// Secret data keys, matching the de facto cert-manager/TLS Secret
// convention (tls.crt/tls.key) plus ca.crt for the CA bundle. Using these
// same keys for both the CA Secret and the two leaf-cert Secrets keeps
// certs.go's helpers (ExtractCARootFromSecret, ExtractServerCertFromSecret)
// reusable across all three.
const (
	CertKey       = "tls.crt"
	PrivateKeyKey = "tls.key"
	CABundleKey   = "ca.crt"
	OldCACertKey  = "old-ca.crt"
)

// Secret names. Fixed (not release-name-derived), like the rest of this
// chart's cross-component references (see ProcessorServiceName), so Go
// code and Helm templates never need to agree on a computed name.
const (
	// CASecretName holds the CA's own certificate and private key
	// (CertKey/PrivateKeyKey), plus, transiently during CA rotation, the
	// previous CA certificate under OldCACertKey. It is never mounted into
	// any pod - the CA private key must stay API-server-only.
	CASecretName = "gateway-protector-ca"

	// ControllerCertSecretName holds the controller's config-stream server
	// certificate/key (CertKey/PrivateKeyKey) plus the CA bundle
	// (CABundleKey) it uses to verify the processor's client certificate.
	ControllerCertSecretName = "gateway-protector-controller-cert"

	// ProcessorClientCertSecretName holds the processor's client
	// certificate/key (CertKey/PrivateKeyKey) plus the CA bundle
	// (CABundleKey) it uses to verify the controller's server certificate.
	ProcessorClientCertSecretName = "gateway-protector-processor-client-cert"

	// ProcessorServerCertSecretName holds the processor's ext_proc server
	// certificate/key (CertKey/PrivateKeyKey) plus the CA bundle
	// (CABundleKey) it uses to verify agentgateway's client certificate.
	ProcessorServerCertSecretName = "gateway-protector-processor-server-cert"

	// AgentgatewayClientCertSecretName holds the client certificate/key
	// (CertKey/PrivateKeyKey) agentgateway presents when dialing the
	// processor's ext_proc service, referenced by name from the chart's
	// AgentgatewayPolicy (backend.tls.mtlsCertificateRef) - see
	// charts/gateway-protector/templates/processor/backend-tls-policy.yaml.
	// Its type is kubernetes.io/tls, as agentgateway requires.
	AgentgatewayClientCertSecretName = "gateway-protector-agentgateway-client-cert"

	// CABundleConfigMapName holds the current CA bundle (CABundleKey) for
	// consumers that read trust bundles from a ConfigMap rather than a
	// Secret - namely agentgateway's AgentgatewayPolicy
	// backend.tls.caCertificateRefs, which only accepts ConfigMaps.
	CABundleConfigMapName = "gateway-protector-ca-bundle"
)

// ControllerServerDNSName is the DNS name the controller's config-stream
// server certificate is issued for, matching the Service the processor
// dials (see internal/controller/processor_config_wiring.go's counterpart
// for the processor's own Service name/port).
const ControllerServerDNSName = "gateway-protector-controller-config-stream"

// ProcessorClientCommonName is the identity presented by the processor's
// client certificate. It is not currently pinned/verified by the
// controller (which only checks that the client certificate chains to the
// CA), but is still set to a stable, recognizable value for logs and any
// future tightening.
const ProcessorClientCommonName = "gateway-protector-processor-client"

// ProcessorServerServiceName is the Service name the processor's ext_proc
// server certificate is issued for (see DNSName), matching
// controller.ProcessorServiceName - the backendRef every generated
// AgentgatewayPolicy points ext_proc traffic at.
const ProcessorServerServiceName = "gateway-protector-processor"

// AgentgatewayClientCommonName is the identity presented by
// agentgateway's client certificate when dialing the processor's ext_proc
// service. Like ProcessorClientCommonName, it is not currently
// pinned/verified beyond chaining to the CA.
const AgentgatewayClientCommonName = "gateway-protector-agentgateway-client"

// Validity durations and rotation lookahead, matching kubewarden's
// admission-controller cert reconciler.
const (
	// CAExpiration is how long a freshly generated CA certificate is valid
	// for.
	CAExpiration = 10 * 365 * 24 * time.Hour
	// LeafExpiration is how long a freshly generated leaf (server/client)
	// certificate is valid for.
	LeafExpiration = 1 * 365 * 24 * time.Hour
	// RotationLookahead is how far ahead of a certificate's actual expiry
	// the reconciler treats it as due for rotation - giving it time to
	// generate and roll out a replacement well before the old one expires.
	RotationLookahead = 60 * 24 * time.Hour
	// ReconcileInterval is how often CertReconciler checks the CA and leaf
	// certificates for rotation.
	ReconcileInterval = 12 * time.Hour
)
