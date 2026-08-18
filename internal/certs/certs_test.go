package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCAAndCertRoundTrip(t *testing.T) {
	now := time.Now()
	caCertPEM, caKeyPEM, err := GenerateCA(now, now.Add(CAExpiration))
	require.NoError(t, err)

	require.NoError(t, VerifyCA(caCertPEM, caKeyPEM, now))

	dnsName := DNSName("gateway-protector-controller-config-stream", "kubewarden")
	certPEM, keyPEM, err := GenerateCert(caCertPEM, caKeyPEM, now, now.Add(LeafExpiration), dnsName)
	require.NoError(t, err)

	pool, err := NewCertPool(caCertPEM)
	require.NoError(t, err)

	assert.NoError(t, VerifyCert(certPEM, keyPEM, pool, dnsName, now))
	// wrong DNS name must fail verification
	require.Error(t, VerifyCert(certPEM, keyPEM, pool, "wrong.example.com", now))
	// a time past expiration must fail verification
	require.Error(t, VerifyCert(certPEM, keyPEM, pool, dnsName, now.Add(LeafExpiration+time.Hour)))
}

func TestVerifyCertRejectsUntrustedCA(t *testing.T) {
	now := time.Now()
	caCertPEM, caKeyPEM, err := GenerateCA(now, now.Add(CAExpiration))
	require.NoError(t, err)

	otherCACertPEM, _, err := GenerateCA(now, now.Add(CAExpiration))
	require.NoError(t, err)

	dnsName := "example.svc"
	certPEM, keyPEM, err := GenerateCert(caCertPEM, caKeyPEM, now, now.Add(LeafExpiration), dnsName)
	require.NoError(t, err)

	otherPool, err := NewCertPool(otherCACertPEM)
	require.NoError(t, err)

	assert.Error(t, VerifyCert(certPEM, keyPEM, otherPool, dnsName, now))
}

func TestVerifyCertInvalidPEMHeader(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)

	// PEM encode with the WRONG header "RSA PRIVATE KEY"
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	pool := x509.NewCertPool()

	err = VerifyCert(certPEM, privateKeyPEM, pool, "example.com", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `expected "EC PRIVATE KEY"`)
}

func TestVerifyCertValidPEMHeader(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	pool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	pool.AddCert(cert)

	assert.NoError(t, VerifyCert(certPEM, privateKeyPEM, pool, "example.com", time.Now()))
}

func TestNewCertPoolMultipleCertificates(t *testing.T) {
	now := time.Now()
	caCertPEM, _, err := GenerateCA(now, now.Add(CAExpiration))
	require.NoError(t, err)

	otherCACertPEM, _, err := GenerateCA(now, now.Add(CAExpiration))
	require.NoError(t, err)

	pool, err := NewCertPool(append(append([]byte{}, caCertPEM...), otherCACertPEM...))
	require.NoError(t, err)
	assert.Len(t, pool.Subjects(), 2) //nolint:staticcheck // Subjects is deprecated but fine for a test assertion.
}

func TestDNSName(t *testing.T) {
	assert.Equal(t, "gateway-protector-controller-config-stream.kubewarden.svc",
		DNSName("gateway-protector-controller-config-stream", "kubewarden"))
}
