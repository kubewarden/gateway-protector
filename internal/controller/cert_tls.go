package controller

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/controller-runtime/pkg/certwatcher"

	"github.com/kubewarden/gateway-protector/internal/certs"
)

// ServerTLSConfig builds the *[tls.Config] the config-stream gRPC server
// uses to require and verify the processor's client certificate, and the
// certwatcher.CertWatcher that keeps the server's own certificate
// (certDir/tls.crt, certDir/tls.key) hot-reloaded from disk - so
// CertReconciler rotating either certificate takes effect without
// restarting the controller.
//
// The CA bundle used to verify the client certificate (certDir/ca.crt) is
// re-read from disk on every handshake via GetConfigForClient, which is
// cheap here: the config stream is one long-lived connection per
// processor replica, so handshakes are rare.
func ServerTLSConfig(certDir string) (*tls.Config, *certwatcher.CertWatcher, error) {
	watcher, err := certwatcher.New(filepath.Join(certDir, certs.CertKey), filepath.Join(certDir, certs.PrivateKeyKey))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate watcher for %q: %w", certDir, err)
	}

	caBundlePath := filepath.Join(certDir, certs.CABundleKey)
	tlsConfig := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			pool, err := loadCertPool(caBundlePath)
			if err != nil {
				return nil, fmt.Errorf("failed to load client CA bundle from %q: %w", caBundlePath, err)
			}

			return &tls.Config{
				MinVersion:     tls.VersionTLS12,
				ClientAuth:     tls.RequireAndVerifyClientCert,
				ClientCAs:      pool,
				GetCertificate: watcher.GetCertificate,
			}, nil
		},
	}

	return tlsConfig, watcher, nil
}

// loadCertPool reads a PEM-encoded (possibly multi-certificate) CA bundle
// from path and parses it into an [x509.CertPool].
func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", path, err)
	}

	pool, err := certs.NewCertPool(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA bundle from %q: %w", path, err)
	}

	return pool, nil
}
