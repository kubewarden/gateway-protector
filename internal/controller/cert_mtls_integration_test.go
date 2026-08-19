package controller

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	"github.com/kubewarden/gateway-protector/internal/certs"
	configstreamv1 "github.com/kubewarden/gateway-protector/internal/configstream/v1"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

const mtlsIntegrationBufSize = 1024 * 1024

// mtlsTestServerName is the config stream's server certificate SAN used
// throughout this file. It doubles as the bufconn dial target's implied
// TLS ServerName: gRPC derives it from the ":authority" it is given
// (here "passthrough:///mtls-bufnet", so "mtls-bufnet" - see
// credentials.tlsCreds.ClientHandshake), which must match a leaf
// certificate's DNS SAN for the handshake to succeed.
const mtlsTestServerName = "mtls-bufnet"

// writeCertFiles writes cert, privateKey, and caBundle to dir as
// tls.crt/tls.key/ca.crt, mirroring what CertReconciler's Secrets look
// like once mounted into a pod - so ServerTLSConfig and
// certs.NewReloadingClientCredentials, both of which only ever read from
// disk, can be exercised exactly as they run in production.
func writeCertFiles(t *testing.T, dir string, cert, privateKey, caBundle []byte) {
	t.Helper()

	require.NoError(t, os.WriteFile(filepath.Join(dir, certs.CertKey), cert, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, certs.PrivateKeyKey), privateKey, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, certs.CABundleKey), caBundle, 0o600))
}

// startMTLSConfigServer starts a real ConfigServer, secured with mTLS
// using ServerTLSConfig, over an in-memory bufconn listener, and returns a
// grpc.DialOption that dials it.
func startMTLSConfigServer(t *testing.T, serverCertDir string) (*ConfigServer, grpc.DialOption) {
	t.Helper()

	tlsConfig, watcher, err := certs.ServerTLSConfig(serverCertDir)
	require.NoError(t, err)

	server := NewConfigServer()

	lis := bufconn.Listen(mtlsIntegrationBufSize)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	configstreamv1.RegisterConfigStreamServiceServer(grpcServer, server)

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)
	_ = watcher // ServerTLSConfig's watcher only matters for hot-reload; this test only needs the initial load.

	dialer := grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() })

	return server, dialer
}

// generateMTLSTestCerts generates a CA, a controller server leaf
// certificate for mtlsTestServerName, and a processor client leaf
// certificate, all as internal/certs would - and returns their PEM bytes
// as (caCert, serverCert, serverKey, clientCert, clientKey).
func generateMTLSTestCerts(t *testing.T) ([]byte, []byte, []byte, []byte, []byte) {
	t.Helper()

	now := time.Now()
	caCert, caKey, err := certs.GenerateCA(now, now.Add(certs.CAExpiration))
	require.NoError(t, err)

	serverCert, serverKey, err := certs.GenerateCert(caCert, caKey, now, now.Add(certs.LeafExpiration), mtlsTestServerName)
	require.NoError(t, err)

	clientCert, clientKey, err := certs.GenerateCert(caCert, caKey, now, now.Add(certs.LeafExpiration), certs.ProcessorClientCommonName)
	require.NoError(t, err)

	return caCert, serverCert, serverKey, clientCert, clientKey
}

// TestConfigStreamMTLSEndToEnd exercises the config stream secured with
// mTLS end to end: a real ConfigServer using ServerTLSConfig (the same
// helper cmd/controller/main.go uses) and a real procconfig.Subscriber
// using certs.NewReloadingClientCredentials (the same helper
// cmd/processor/main.go uses), both reading their certificates/CA bundle
// from disk exactly as they do mounted from a Secret in production.
func TestConfigStreamMTLSEndToEnd(t *testing.T) {
	caCert, serverCert, serverKey, clientCert, clientKey := generateMTLSTestCerts(t)

	serverCertDir := t.TempDir()
	writeCertFiles(t, serverCertDir, serverCert, serverKey, caCert)

	clientCertDir := t.TempDir()
	writeCertFiles(t, clientCertDir, clientCert, clientKey, caCert)

	server, dialer := startMTLSConfigServer(t, serverCertDir)
	publisher := &GRPCPublisher{Server: server}

	subscriber := procconfig.NewSubscriber("passthrough:///"+mtlsTestServerName, "test-replica",
		nil, certs.NewReloadingClientCredentials(clientCertDir), dialer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	received := make(chan *procconfig.Snapshot, 1)
	go func() { _ = subscriber.Run(ctx, func(s *procconfig.Snapshot) { received <- s }) }()

	cfg := &procconfig.Config{
		Directives: map[string]string{"a": "SecRuleEngine On"},
		Routes: []procconfig.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &procconfig.WAFRef{EngineKey: "a"}},
		},
	}
	require.NoError(t, publisher.Publish(ctx, cfg))

	select {
	case snapshot := <-received:
		_, matched := snapshot.Match("example.com", "/")
		assert.True(t, matched, "expected the published config to reach the subscriber over mTLS")
	case <-ctx.Done():
		t.Fatal("timed out waiting for the subscriber to receive the config over mTLS")
	}
}

// TestConfigStreamMTLSRejectsClientWithoutCertificate asserts that the
// config stream server, once secured with ServerTLSConfig, refuses a
// client that presents no certificate at all - proving that
// tls.RequireAndVerifyClientCert (see ServerTLSConfig) actually takes
// effect rather than silently accepting plaintext-equivalent clients.
func TestConfigStreamMTLSRejectsClientWithoutCertificate(t *testing.T) {
	caCert, serverCert, serverKey, _, _ := generateMTLSTestCerts(t)

	serverCertDir := t.TempDir()
	writeCertFiles(t, serverCertDir, serverCert, serverKey, caCert)

	_, dialer := startMTLSConfigServer(t, serverCertDir)

	pool, err := certs.NewCertPool(caCert)
	require.NoError(t, err)

	// A client that trusts the server's CA (so it isn't the server cert
	// verification that fails) but presents no client certificate of its
	// own must still be rejected by RequireAndVerifyClientCert.
	noClientCertCreds := credentials.NewTLS(&tls.Config{RootCAs: pool})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := grpc.NewClient("passthrough:///"+mtlsTestServerName,
		grpc.WithTransportCredentials(noClientCertCreds), dialer)
	require.NoError(t, err, "NewClient itself only fails on option errors; the handshake happens lazily")
	defer conn.Close()

	client := configstreamv1.NewConfigStreamServiceClient(conn)
	stream, err := client.StreamConfig(ctx)
	if err == nil {
		err = stream.Send(&configstreamv1.StreamConfigRequest{
			Message: &configstreamv1.StreamConfigRequest_Subscribe{
				Subscribe: &configstreamv1.Subscribe{SubscriberId: "test-replica-no-cert"},
			},
		})
	}
	if err == nil {
		_, err = stream.Recv()
	}
	assert.Error(t, err, "expected the server to reject a client presenting no certificate")
}
