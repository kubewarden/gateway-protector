package processor

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	"github.com/kubewarden/gateway-protector/internal/certs"
	"github.com/kubewarden/gateway-protector/internal/processor/config"
)

const mtlsExtProcBufSize = 1024 * 1024

// mtlsExtProcServerName is the ext_proc server certificate's SAN used
// throughout this file - see cert_mtls_integration_test.go in
// internal/controller for why this must match gRPC's implied TLS
// ServerName for the bufconn dial target used below.
const mtlsExtProcServerName = "mtls-ext-proc-bufnet"

// writeExtProcCertFiles writes cert, privateKey, and caBundle to dir as
// tls.crt/tls.key/ca.crt, mirroring what CertReconciler's Secrets look
// like once mounted into a pod (see cert_reconciler.go's
// ProcessorServerCertSecretName/AgentgatewayClientCertSecretName), so
// certs.ServerTLSConfig and certs.NewReloadingClientCredentials - both of
// which only ever read from disk - are exercised exactly as they run in
// production.
func writeExtProcCertFiles(t *testing.T, dir string, cert, privateKey, caBundle []byte) {
	t.Helper()

	require.NoError(t, os.WriteFile(filepath.Join(dir, certs.CertKey), cert, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, certs.PrivateKeyKey), privateKey, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, certs.CABundleKey), caBundle, 0o600))
}

// startMTLSExtProcServer starts a real processor Server, secured with
// mTLS using certs.ServerTLSConfig (the same helper cmd/processor/main.go
// uses for --ext-proc-cert-dir), over an in-memory bufconn listener, and
// returns a grpc.DialOption that dials it.
func startMTLSExtProcServer(t *testing.T, cfg *config.Config, serverCertDir string) grpc.DialOption {
	t.Helper()

	require.NoError(t, config.Validate(cfg))
	snapshot, err := config.Compile(cfg, nil)
	require.NoError(t, err)

	tlsConfig, watcher, err := certs.ServerTLSConfig(serverCertDir)
	require.NoError(t, err)
	_ = watcher // only matters for hot-reload; this test only needs the initial load.

	server := New(snapshot, nil)

	lis := bufconn.Listen(mtlsExtProcBufSize)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(grpcServer, server)

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() })
}

// generateMTLSExtProcTestCerts generates a CA, a processor ext_proc server
// leaf certificate for mtlsExtProcServerName, and an agentgateway client
// leaf certificate, all as internal/certs would - and returns their PEM
// bytes as (caCert, serverCert, serverKey, clientCert, clientKey).
func generateMTLSExtProcTestCerts(t *testing.T) ([]byte, []byte, []byte, []byte, []byte) {
	t.Helper()

	now := time.Now()
	caCert, caKey, err := certs.GenerateCA(now, now.Add(certs.CAExpiration))
	require.NoError(t, err)

	serverCert, serverKey, err := certs.GenerateCert(caCert, caKey, now, now.Add(certs.LeafExpiration), mtlsExtProcServerName)
	require.NoError(t, err)

	clientCert, clientKey, err := certs.GenerateCert(caCert, caKey, now, now.Add(certs.LeafExpiration), certs.AgentgatewayClientCommonName)
	require.NoError(t, err)

	return caCert, serverCert, serverKey, clientCert, clientKey
}

// TestExtProcMTLSEndToEnd exercises the ext_proc service secured with mTLS
// end to end: a real Server behind certs.ServerTLSConfig (the same helper
// cmd/processor/main.go uses) and a real ext_proc client using
// certs.NewReloadingClientCredentials (the same helper agentgateway's
// client cert Secret would back), both reading their certificates/CA
// bundle from disk exactly as they do mounted from a Secret in
// production.
func TestExtProcMTLSEndToEnd(t *testing.T) {
	caCert, serverCert, serverKey, clientCert, clientKey := generateMTLSExtProcTestCerts(t)

	serverCertDir := t.TempDir()
	writeExtProcCertFiles(t, serverCertDir, serverCert, serverKey, caCert)

	clientCertDir := t.TempDir()
	writeExtProcCertFiles(t, clientCertDir, clientCert, clientKey, caCert)

	cfg := &config.Config{
		Directives: map[string]string{"a": "SecRuleEngine On"},
		Routes: []config.Route{
			{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "a"}},
		},
	}
	dialer := startMTLSExtProcServer(t, cfg, serverCertDir)

	conn, err := grpc.NewClient("passthrough:///"+mtlsExtProcServerName,
		grpc.WithTransportCredentials(certs.NewReloadingClientCredentials(clientCertDir)), dialer)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := envoy_service_ext_proc_v3.NewExternalProcessorClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Process(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Send(requestHeadersMessage("example.com", "/")))
	resp, err := stream.Recv()
	require.NoError(t, err)

	require.IsType(t, &envoy_service_ext_proc_v3.ProcessingResponse_RequestHeaders{}, resp.GetResponse())
	assert.Equal(t, envoy_service_ext_proc_v3.CommonResponse_CONTINUE, resp.GetRequestHeaders().GetResponse().GetStatus())

	require.NoError(t, stream.CloseSend())
}

// TestExtProcMTLSRejectsClientWithoutCertificate asserts that the ext_proc
// server, once secured with certs.ServerTLSConfig, refuses a client that
// presents no certificate at all - proving that
// tls.RequireAndVerifyClientCert actually takes effect rather than
// silently accepting plaintext-equivalent clients.
func TestExtProcMTLSRejectsClientWithoutCertificate(t *testing.T) {
	caCert, serverCert, serverKey, _, _ := generateMTLSExtProcTestCerts(t)

	serverCertDir := t.TempDir()
	writeExtProcCertFiles(t, serverCertDir, serverCert, serverKey, caCert)

	cfg := &config.Config{
		Directives: map[string]string{"a": "SecRuleEngine On"},
		Routes:     []config.Route{{Host: "example.com", PathPrefix: "/", WAF: &config.WAFRef{EngineKey: "a"}}},
	}
	dialer := startMTLSExtProcServer(t, cfg, serverCertDir)

	pool, err := certs.NewCertPool(caCert)
	require.NoError(t, err)

	// A client that trusts the server's CA (so it isn't the server cert
	// verification that fails) but presents no client certificate of its
	// own must still be rejected by RequireAndVerifyClientCert.
	noClientCertCreds := credentials.NewTLS(&tls.Config{RootCAs: pool})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := grpc.NewClient("passthrough:///"+mtlsExtProcServerName,
		grpc.WithTransportCredentials(noClientCertCreds), dialer)
	require.NoError(t, err, "NewClient itself only fails on option errors; the handshake happens lazily")
	t.Cleanup(func() { _ = conn.Close() })

	client := envoy_service_ext_proc_v3.NewExternalProcessorClient(conn)
	stream, err := client.Process(ctx)
	if err == nil {
		err = stream.Send(requestHeadersMessage("example.com", "/"))
	}
	if err == nil {
		_, err = stream.Recv()
	}
	assert.Error(t, err, "expected the server to reject a client presenting no certificate")
}
