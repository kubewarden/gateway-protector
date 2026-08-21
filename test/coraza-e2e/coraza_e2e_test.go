// Package corazae2e runs Coraza's own connector end-to-end suite
// (github.com/corazawaf/coraza/v3/http/e2e) against this project's ext_proc
// processor, fronted by a real agentgateway instance.
//
// The suite is purpose-built by the Coraza project to verify that a
// connector wires the WAF into every HTTP processing phase correctly: it
// loads a fixed directive block (e2e.Directives) and fires requests that
// must be blocked at each of the four phases (request headers, request
// body, response headers, response body), plus XSS/SQLi operator checks, a
// malicious User-Agent check, and an SSE test asserting responses still
// stream through un-buffered. It even health-checks that the exact
// directive block is live (a rule returning 424 when the "coraza-e2e"
// request header is missing).
//
// Topology (see TestCorazaE2E):
//
//	e2e.Run() --HTTP--> URI canonicalizer (in-process reverse proxy,
//	                     |                 see startURICanonicalizer)
//	                     '--HTTP--> agentgateway (container, ext_proc policy)
//	                                 |--gRPC ext_proc--> processor (in-process Server)
//	                                 '--HTTP-----------> go-httpbin (container)
//
// The canonicalizer re-encodes the suite's RFC-invalid raw query strings
// (e.g. its XSS test's literal "?arg=<script>alert(0)</script>") into the
// percent-encoded form a real client would send: agentgateway's RFC-strict
// HTTP stack rejects the raw form with 400 before ext_proc/the WAF ever
// sees it, while the suite hardcodes an expected 403. The attack is denied
// either way; assertRawInvalidURIRejectedByGateway separately bypasses the
// canonicalizer to pin down that gateway-level 400 on the raw form.
//
// The processor runs in-process with its Snapshot injected directly via
// SetSnapshot: the controller/config-stream path deliberately isn't part
// of this harness - it is already covered end-to-end by test/e2e (kind +
// real controller). What this suite uniquely exercises is the ext_proc
// phase mapping between agentgateway and the processor, so agentgateway's
// extProc policy below mirrors the ProcessingOptions the controller wires
// in production (see internal/controller.desiredWiringPolicy): header
// modes Send, body modes FullDuplexStreamed, trailer modes Skip.
package corazae2e

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	coraza_e2e "github.com/corazawaf/coraza/v3/http/e2e"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"

	"github.com/kubewarden/gateway-protector/internal/processor"
	"github.com/kubewarden/gateway-protector/internal/processor/config"
	"github.com/kubewarden/gateway-protector/test/internal/containerlog"
)

const (
	// agentgatewayImage is pinned to the same version test/e2e installs
	// via the Helm chart, so both suites exercise the same data plane.
	agentgatewayImage = "ghcr.io/agentgateway/agentgateway:v1.3.1"

	// httpbinImage provides the upstream the Coraza suite expects: it
	// relies on go-httpbin's /status, /anything, /response-headers and
	// /sse endpoints.
	httpbinImage = "mccutchen/go-httpbin:2.22.1"

	// gatewayPort is the HTTP port agentgateway binds inside its
	// container (see agentgatewayConfigTemplate).
	gatewayPort = "8081"

	// httpbinPort is go-httpbin's listen port inside its container.
	httpbinPort = "8080"

	// engineKey is the key the e2e directive block is compiled under in
	// the processor's Snapshot. Its value is arbitrary: it only links
	// the catch-all route to the engine.
	engineKey = "coraza-e2e"
)

// agentgatewayConfigTemplate is agentgateway's standalone ("-f
// config.yaml") configuration: one HTTP bind whose single catch-all route
// proxies to the go-httpbin container, with an extProc policy pointing at
// the in-process processor on the host. The processingOptions mirror what
// the controller renders into the generated AgentgatewayPolicy in
// production (internal/controller.desiredWiringPolicy), with both body
// phases enabled since e2e.Directives inspects request and response
// bodies. The two %s verbs are the ext_proc host:port and the httpbin
// host:port.
const agentgatewayConfigTemplate = `binds:
- port: ` + gatewayPort + `
  listeners:
  - protocol: HTTP
    routes:
    - name: coraza-e2e
      policies:
        extProc:
          host: %s
          failureMode: failClosed
          processingOptions:
            requestHeaderMode: send
            responseHeaderMode: send
            requestBodyMode: fullDuplexStreamed
            responseBodyMode: fullDuplexStreamed
            requestTrailerMode: skip
            responseTrailerMode: skip
      backends:
      - host: %s
`

// startProcessor compiles Coraza's e2e directive block into a Snapshot
// with a single catch-all route and serves the ext_proc gRPC service on an
// ephemeral loopback port, returning that port. The server is shut down
// via t.Cleanup.
func startProcessor(t *testing.T, logger *slog.Logger) int {
	t.Helper()

	cfg := &config.Config{
		Directives: map[string]string{engineKey: coraza_e2e.Directives},
		Routes: []config.Route{{
			Host:       "*",
			PathPrefix: "/",
			WAF:        &config.WAFRef{EngineKey: engineKey},
		}},
	}
	require.NoError(t, config.Validate(cfg))

	snapshot, err := config.Compile(cfg, logger)
	require.NoError(t, err, "failed to compile Coraza's e2e directives")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(grpcServer, processor.New(snapshot, logger))

	go func() {
		if serveErr := grpcServer.Serve(listener); serveErr != nil {
			logger.Error("ext_proc gRPC server exited", slog.Any("error", serveErr))
		}
	}()
	t.Cleanup(grpcServer.Stop)

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok, "listener address is not TCP")

	return tcpAddr.Port
}

// invalidQueryChars are characters RFC 3986 forbids unencoded in a query
// string that Coraza's e2e suite nevertheless sends raw (its XSS test
// requests "?arg=<script>alert(0)</script>" literally).
const invalidQueryChars = "<>\"{}|\\^`"

// startURICanonicalizer serves a minimal reverse proxy in front of the
// gateway that re-encodes RFC-invalid query strings, and returns its
// host:port.
//
// It exists because of a deliberate difference between agentgateway and
// the proxies Coraza's e2e suite was written against: agentgateway's HTTP
// stack (hyper) is RFC-strict and rejects a raw "<script>" request-target
// with 400 before routing - and thus before ext_proc/the WAF - ever sees
// it, while Envoy & co. are lenient and let the WAF answer 403. The
// attack is denied either way, but the suite hardcodes 403, so the raw
// URL is canonicalized into the percent-encoded form any browser would
// send, which does reach the WAF and exercises its decoding chain
// (t:urlDecodeUni). TestCorazaE2E separately asserts the raw form still
// gets agentgateway's 400.
func startURICanonicalizer(t *testing.T, gatewayEndpoint string) string {
	t.Helper()

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = gatewayEndpoint
			pr.Out.Host = pr.In.Host

			if strings.ContainsAny(pr.Out.URL.RawQuery, invalidQueryChars) {
				pr.Out.URL.RawQuery = pr.Out.URL.Query().Encode()
			}
		},
		// Flush every write immediately so the suite's SSE streaming
		// test observes the gateway's (and processor's) real
		// streaming behavior, not this shim's buffering.
		FlushInterval: -1,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Logf("URI canonicalizer exited: %v", serveErr)
		}
	}()
	t.Cleanup(func() { _ = server.Close() })

	return listener.Addr().String()
}

// assertRawInvalidURIRejectedByGateway sends the e2e suite's XSS request
// byte-for-byte (raw, unencoded "<script>" in the request-target) straight
// to agentgateway and asserts it is denied with agentgateway's own 400:
// this is the request startURICanonicalizer has to re-encode for the
// suite, and this assertion pins down that the raw form stays denied at
// the gateway layer.
func assertRawInvalidURIRejectedByGateway(t *testing.T, gatewayEndpoint string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", gatewayEndpoint, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = fmt.Fprintf(conn, "GET /anything?arg=<script>alert(0)</script> HTTP/1.1\r\nHost: %s\r\ncoraza-e2e: ok\r\n\r\n", gatewayEndpoint)
	require.NoError(t, err)

	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(reply[:n]), "HTTP/1.1 400"),
		"expected agentgateway to reject the raw RFC-invalid URI with 400, got: %q", string(reply[:n]))
}

// TestCorazaE2E wires the full topology together and hands control to
// Coraza's e2e.Run, which performs its own health checks (including
// verifying the exact e2e directive block is enforced) before running the
// per-phase block/pass assertions.
func TestCorazaE2E(t *testing.T) {
	ctx := context.Background()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	processorPort := startProcessor(t, logger)

	testNetwork, err := network.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		if removeErr := testNetwork.Remove(context.Background()); removeErr != nil {
			t.Logf("failed to remove test network: %v", removeErr)
		}
	})

	httpbin, err := testcontainers.Run(ctx,
		httpbinImage,
		network.WithNetwork([]string{"httpbin"}, testNetwork),
		testcontainers.WithExposedPorts(httpbinPort+"/tcp"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort(httpbinPort+"/tcp")),
	)
	testcontainers.CleanupContainer(t, httpbin)
	require.NoError(t, err, "failed to start go-httpbin")

	gatewayConfig := fmt.Sprintf(agentgatewayConfigTemplate,
		net.JoinHostPort(testcontainers.HostInternal, strconv.Itoa(processorPort)),
		"httpbin:"+httpbinPort)
	gatewayConfigPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(gatewayConfigPath, []byte(gatewayConfig), 0o600))

	gateway, err := testcontainers.Run(ctx,
		agentgatewayImage,
		testcontainers.WithCmd("-f", "/etc/agentgateway/config.yaml"),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			HostFilePath:      gatewayConfigPath,
			ContainerFilePath: "/etc/agentgateway/config.yaml",
			FileMode:          0o444,
		}),
		network.WithNetwork([]string{"agentgateway"}, testNetwork),
		// Lets the container reach the in-process processor on the
		// host as host.testcontainers.internal:<port>.
		testcontainers.WithHostPortAccess(processorPort),
		testcontainers.WithExposedPorts(gatewayPort+"/tcp"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort(gatewayPort+"/tcp")),
		testcontainers.WithLogConsumerConfig(containerlog.OnFailure(t, "agentgateway")),
	)
	testcontainers.CleanupContainer(t, gateway)
	require.NoError(t, err, "failed to start agentgateway")

	gatewayEndpoint, err := gateway.PortEndpoint(ctx, gatewayPort, "")
	require.NoError(t, err)

	httpbinEndpoint, err := httpbin.PortEndpoint(ctx, httpbinPort, "")
	require.NoError(t, err)

	// The suite's entrypoint is a thin URI-canonicalizing shim in front
	// of the gateway - see startURICanonicalizer for why.
	suiteEntrypoint := startURICanonicalizer(t, gatewayEndpoint)

	require.NoError(t, coraza_e2e.Run(coraza_e2e.Config{
		// The processor answers every phase interruption with an
		// ImmediateResponse carrying the rule's status code, so the
		// suite must see real 403s even at the response-body phase -
		// no nulled-body fallback.
		NulledBody:        false,
		ProxiedEntrypoint: suiteEntrypoint,
		HttpbinEntrypoint: httpbinEndpoint,
	}))

	assertRawInvalidURIRejectedByGateway(t, gatewayEndpoint)
}
