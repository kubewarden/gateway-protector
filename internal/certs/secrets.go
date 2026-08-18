package certs

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// ExtractCA extracts the CA certificate and private key (both PEM encoded)
// from the CA Secret.
func ExtractCA(caSecret *corev1.Secret) ([]byte, []byte, error) {
	caCert, found := caSecret.Data[CertKey]
	if !found || len(caCert) == 0 {
		return nil, nil, fmt.Errorf("CA certificate could not be extracted from secret %q", caSecret.GetName())
	}

	caPrivateKey, found := caSecret.Data[PrivateKeyKey]
	if !found || len(caPrivateKey) == 0 {
		return nil, nil, fmt.Errorf("CA private key could not be extracted from secret %q", caSecret.GetName())
	}

	return caCert, caPrivateKey, nil
}

// ExtractLeafCert extracts the leaf certificate and private key (both PEM
// encoded) from a leaf-cert Secret (controller or processor).
func ExtractLeafCert(leafSecret *corev1.Secret) ([]byte, []byte, error) {
	cert, found := leafSecret.Data[CertKey]
	if !found || len(cert) == 0 {
		return nil, nil, fmt.Errorf("certificate could not be extracted from secret %q", leafSecret.GetName())
	}

	privateKey, found := leafSecret.Data[PrivateKeyKey]
	if !found || len(privateKey) == 0 {
		return nil, nil, fmt.Errorf("private key could not be extracted from secret %q", leafSecret.GetName())
	}

	return cert, privateKey, nil
}
