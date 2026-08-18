// Package certs implements a self-contained, cert-manager-free mTLS setup
// for the controller's config stream: generating a self-signed CA and
// ECDSA leaf certificates signed by it, and verifying both ahead of
// expiry so callers can decide when to rotate. This mirrors the approach
// used by kubewarden's admission controller (see
// github.com/kubewarden/adm-controller/internal/certs), reused here
// verbatim except for the CA's CommonName.
package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	startValue          = 1
	maxBitLength        = 128
	caCommonName        = "gateway-protector-ca"
	certificatePEMType  = "CERTIFICATE"
	ecPrivateKeyPEMType = "EC PRIVATE KEY"
)

// GenerateCA generates a self-signed CA root certificate and private key in PEM format.
// It accepts validity bounds as parameters.
func GenerateCA(notBefore, notAfter time.Time) ([]byte, []byte, error) {
	serialNumberUpperBound := new(big.Int).Lsh(big.NewInt(startValue), maxBitLength)
	serialNumber, err := rand.Int(rand.Reader, serialNumberUpperBound)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot init serial number: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create private key: %w", err)
	}

	caCert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: caCommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		&caCert,
		&caCert,
		&privateKey.PublicKey,
		privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create certificate: %w", err)
	}

	caCertPEM, err := pemEncodeCertificate(caCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode certificate: %w", err)
	}

	privateKeyPEM, err := pemEncodePrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode private key: %w", err)
	}

	return caCertPEM, privateKeyPEM, nil
}

// GenerateCert generates a certificate and private key signed by the provided CA in PEM format.
// It accepts the CA root certificate and private key, validity bounds, and DNS name as parameters.
func GenerateCert(caCertPEM []byte,
	caPrivateKeyPEM []byte,
	notBefore time.Time,
	notAfter time.Time,
	dnsName string,
) ([]byte, []byte, error) {
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, nil, errors.New("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing ca root certificate: %w", err)
	}

	caPrivateKeyBlock, _ := pem.Decode(caPrivateKeyPEM)
	if caPrivateKeyBlock == nil {
		return nil, nil, errors.New("failed to decode CA private key PEM")
	}
	caPrivateKey, err := x509.ParseECPrivateKey(caPrivateKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing ca root private key: %w", err)
	}

	serialNumberUpperBound := new(big.Int).Lsh(big.NewInt(startValue), maxBitLength)
	serialNumber, err := rand.Int(rand.Reader, serialNumberUpperBound)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate serialNumber for certificate: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create private key: %w", err)
	}

	cert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:    []string{dnsName},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&cert,
		caCert,
		&privateKey.PublicKey,
		caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create certificate: %w", err)
	}

	certPEM, err := pemEncodeCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode certificate: %w", err)
	}

	privateKeyPEM, err := pemEncodePrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode private key: %w", err)
	}

	return certPEM, privateKeyPEM, nil
}

// pemEncodeCertificate encodes a certificate to PEM format.
func pemEncodeCertificate(certificate []byte) ([]byte, error) {
	certificatePEM := new(bytes.Buffer)

	err := pem.Encode(certificatePEM, &pem.Block{
		Type:  certificatePEMType,
		Bytes: certificate,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("PEM encode failure: %w", err)
	}

	return certificatePEM.Bytes(), nil
}

// pemEncodePrivateKey encodes a private key to PEM format.
func pemEncodePrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal private key: %w", err)
	}
	privateKeyPEM := new(bytes.Buffer)

	err = pem.Encode(privateKeyPEM, &pem.Block{
		Type:  ecPrivateKeyPEMType,
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("PEM encode failure: %w", err)
	}

	return privateKeyPEM.Bytes(), nil
}

// NewCertPool creates a new [x509.CertPool] from a PEM-encoded certificate that may contain multiple certificates.
func NewCertPool(certPEM []byte) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	for {
		var block *pem.Block
		block, certPEM = pem.Decode(certPEM)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %w", err)
		}

		certPool.AddCert(cert)
	}

	return certPool, nil
}

// VerifyCA verifies that a self-signed CA certificate (and, if provided,
// its private key) is valid at the given time.
func VerifyCA(caCertPEM, caPrivateKeyPEM []byte, at time.Time) error {
	pool, err := NewCertPool(caCertPEM)
	if err != nil {
		return fmt.Errorf("failed to create cert pool: %w", err)
	}

	if err = VerifyCert(caCertPEM, caPrivateKeyPEM, pool, "", at); err != nil {
		return fmt.Errorf("failed to verify CA certificate: %w", err)
	}

	return nil
}

// VerifyCert verifies that certPEM (optionally paired with privateKeyPEM)
// chains up to certPool, is valid for dnsName (skipped when dnsName is
// empty, as when verifying a CA against itself), and is valid at the given
// time.
func VerifyCert(certPEM, privateKeyPEM []byte, certPool *x509.CertPool, dnsName string, at time.Time) error {
	// Decode and parse the certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	// Verify the private key
	if privateKeyPEM != nil {
		block, _ := pem.Decode(privateKeyPEM)
		if block == nil {
			return errors.New("failed to decode private key PEM")
		}
		// We always create EC keys; the PEM header is checked strictly so
		// that a key pair written with a wrong header by some future bug
		// forces regeneration rather than silently failing to load.
		if block.Type != ecPrivateKeyPEMType {
			return fmt.Errorf("private key has invalid PEM header, expected %q", ecPrivateKeyPEMType)
		}

		if _, err = tls.X509KeyPair(certPEM, privateKeyPEM); err != nil {
			return fmt.Errorf("key pair is invalid: %w", err)
		}
	}

	// Set up the verification options
	opts := x509.VerifyOptions{
		Roots:       certPool,
		DNSName:     dnsName,
		CurrentTime: at,
	}

	// Verify the certificate
	if _, err = cert.Verify(opts); err != nil {
		return fmt.Errorf("the certificate is invalid: %w", err)
	}

	return nil
}

// DNSName returns the in-cluster DNS name of a Service, as used both when
// generating a leaf certificate's SAN and when verifying it.
func DNSName(serviceName, namespace string) string {
	return fmt.Sprintf("%s.%s.svc", serviceName, namespace)
}
