package certs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc/credentials"
)

// ReloadingClientCredentials is a gRPC credentials.TransportCredentials
// implementation for a client presenting a certificate: every connection
// attempt (the initial dial, and every automatic reconnect gRPC performs
// after a transport failure) re-reads the client certificate/key and the
// CA bundle from certDir from scratch, so a certificate rotated by
// CertReconciler (see internal/controller/cert_reconciler.go) - which
// writes a new Secret that eventually lands on disk via the kubelet's
// mounted-Secret sync - takes effect on this client without restarting
// the process or resubscribing.
type ReloadingClientCredentials struct {
	certDir string
}

// NewReloadingClientCredentials returns client credentials that load the
// client certificate/key (CertKey/PrivateKeyKey) and the CA bundle used to
// verify the server (CABundleKey) from certDir on every handshake.
func NewReloadingClientCredentials(certDir string) *ReloadingClientCredentials {
	return &ReloadingClientCredentials{certDir: certDir}
}

var _ credentials.TransportCredentials = (*ReloadingClientCredentials)(nil)

// ClientHandshake implements credentials.TransportCredentials.
func (c *ReloadingClientCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(c.certDir, CertKey), filepath.Join(c.certDir, PrivateKeyKey))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client certificate/key from %q: %w", c.certDir, err)
	}

	caBundlePEM, err := os.ReadFile(filepath.Join(c.certDir, CABundleKey))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA bundle from %q: %w", c.certDir, err)
	}

	pool, err := NewCertPool(caBundlePEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build CA pool from %q: %w", c.certDir, err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}

	//nolint:wrapcheck // delegating to the stdlib TLS credentials implementation, no extra context to add.
	return credentials.NewTLS(tlsConfig).ClientHandshake(ctx, authority, rawConn)
}

// ServerHandshake implements credentials.TransportCredentials. It always
// fails: ReloadingClientCredentials is client-only.
func (c *ReloadingClientCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("ReloadingClientCredentials does not support server-side handshakes")
}

// Info implements credentials.TransportCredentials.
func (c *ReloadingClientCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}

// Clone implements credentials.TransportCredentials.
func (c *ReloadingClientCredentials) Clone() credentials.TransportCredentials {
	return &ReloadingClientCredentials{certDir: c.certDir}
}

// OverrideServerName implements credentials.TransportCredentials. It is a
// no-op: this method is deprecated and unused by gRPC (callers should use
// grpc.WithAuthority instead), and ClientHandshake already derives the TLS
// ServerName from the authority gRPC passes it.
func (c *ReloadingClientCredentials) OverrideServerName(string) error {
	return nil
}
