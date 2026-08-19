package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
)

// ServerTLSConfig builds the *[tls.Config] a gRPC server uses to require
// and verify a client certificate, and the certwatcher.CertWatcher that
// keeps the server's own certificate (certDir/tls.crt, certDir/tls.key)
// hot-reloaded from disk - so CertReconciler rotating either certificate
// takes effect without restarting the process.
//
// Both the controller's config-stream server and the processor's ext_proc
// server use this: certDir points at whichever mounted Secret holds that
// server's own certificate/key plus the CA bundle (certDir/ca.crt) used to
// verify its client's certificate. The CA bundle is re-read from disk on
// every handshake via GetConfigForClient, which is cheap here: both
// servers see only long-lived, low-frequency connection setups (one
// config-stream connection per processor replica; ext_proc connections
// are set up per agentgateway worker, not per request).
//
// The returned CertWatcher must be started (either via
// manager.Manager.Add, for the controller, or by calling Start in a
// goroutine, for the plain-Go processor) for the hot-reload to actually
// happen; until then GetCertificate keeps serving the certificate loaded
// at construction time.
func ServerTLSConfig(certDir string) (*tls.Config, *certwatcher.CertWatcher, error) {
	watcher, err := certwatcher.New(filepath.Join(certDir, CertKey), filepath.Join(certDir, PrivateKeyKey))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate watcher for %q: %w", certDir, err)
	}

	caBundlePath := filepath.Join(certDir, CABundleKey)
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

	pool, err := NewCertPool(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA bundle from %q: %w", path, err)
	}

	return pool, nil
}
