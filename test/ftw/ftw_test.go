// Package ftw runs the OWASP Core Rule Set's own regression test corpus
// (via go-ftw, the CRS project's official test runner) against this
// project's ext_proc processor, fronted by a real agentgateway instance.
// This is the CRS project's own compliance suite: passing it is the
// evidence behind any "CRS compliant" claim this project makes, in the
// same way running it is how every other CRS connector (Envoy, nginx,
// Apache modules, etc.) substantiates that claim.
//
// Where test/coraza-e2e verifies the ext_proc *wiring* (all four phases
// reachable, bodies not truncated, blocking/withholding semantics
// correct) using Coraza's own small, purpose-built connector suite, this
// package verifies CRS *rule fidelity* at scale: ~1000 individual
// attack/benign test cases spanning every CRS rule file, run through the
// full stack rather than directly against Coraza.
//
// Topology (see TestCRSRegression):
//
//	go-ftw (host CLI) --HTTP--> agentgateway (container, ext_proc policy)
//	                             |--gRPC ext_proc--> processor (in-process Server)
//	                             '--HTTP-----------> albedo (container)
//
// The corpus runs in DetectionOnly mode (see testdata/crs-ftw-setup.conf):
// go-ftw verifies which rule fired by correlating each test's unique
// X-CRS-Test marker header against matched-rule log lines (see
// --waf-matched-rules-log in cmd/processor, internal/processor/config's
// WithMatchedRuleWriter), not by asserting on the HTTP response - so this
// harness never needs the processor's own blocking path to run at all for
// most tests (the handful that do assert on status codes are configured
// via testdata/overrides.yml's "output.status", same as upstream).
//
// This harness deliberately does not force a Host header onto test
// requests: go-ftw's generated config only overrides dest_addr/port (see
// ftwInputOverride), and both agentgateway's route and the processor's
// engine-selection table are catch-all entries that match any Host. Several CRS
// tests use a specific Host header - or its absence - as part of the
// attack they exercise, so every test's Host header arrives exactly as
// the CRS authors wrote it, and no overrides are needed for those tests.
package ftw

import (
	"archive/tar"
	"compress/gzip"
	"context"
	_ "embed"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/mod/modfile"
	"google.golang.org/grpc"
	"sigs.k8s.io/yaml"

	"github.com/kubewarden/gateway-protector/internal/processor"
	"github.com/kubewarden/gateway-protector/internal/processor/config"
	"github.com/kubewarden/gateway-protector/test/internal/containerlog"
)

const (
	// agentgatewayImage is pinned to the same version test/e2e and
	// test/coraza-e2e use, so every suite exercises the same data plane.
	agentgatewayImage = "ghcr.io/agentgateway/agentgateway:v1.3.1"

	// albedoImage is the CRS project's own purpose-built test upstream
	// (https://github.com/coreruleset/albedo): unlike a generic
	// echo/httpbin server, it implements the specific response behaviors
	// (status codes, header/body reflection) individual regression tests
	// assert on. Pinned to the same version the reference connector's
	// ftw setup uses.
	albedoImage = "ghcr.io/coreruleset/albedo:0.3.0"

	// albedoMaxBodySize is albedo's own request body size cap; several
	// REQUEST_BODY-related regression tests send bodies close to CRS's
	// own configured limits (see testdata/crs-ftw-setup.conf's
	// tx.max_file_size/tx.combined_file_sizes), so albedo's own limit
	// must comfortably exceed those.
	albedoMaxBodySize = "15728640" // 15 MiB, matching the reference connector's setup

	// gatewayPort/albedoPort are the ports each container listens on
	// inside its own network namespace.
	gatewayPort = "8081"
	albedoPort  = "8080"

	// engineKey is the key the CRS directive block is compiled under in
	// the processor's Snapshot; arbitrary, it only links the catch-all
	// route to the engine.
	engineKey = "crs-ftw"

	// goFtwModule/goFtwVersion pin the exact go-ftw release this harness
	// invokes via `go run`, independent of this module's own go.mod (see
	// runGoFTW).
	goFtwModule  = "github.com/coreruleset/go-ftw/v2"
	goFtwVersion = "v2.4.0"

	// crsCoreRuleSetModulePath is the Go module providing the embedded
	// OWASP Core Rule Set - see embeddedCRSVersion, and
	// internal/processor/config.EmbeddedCRSVersion's own doc comment for
	// why that function can't be used here (it relies on
	// runtime/debug.ReadBuildInfo, which "go test" binaries don't
	// populate).
	crsCoreRuleSetModulePath = "github.com/corazawaf/coraza-coreruleset/v4"
)

// crsFTWDirectives is the complete SecLang directive block the CRS
// regression suite's engine is compiled from - see
// testdata/crs-ftw-setup.conf's own doc comment for its full structure
// (skeleton + tx.* setup + the X-CRS-Test marker rule) and how it lines
// up with what production renders.
//
//go:embed testdata/crs-ftw-setup.conf
var crsFTWDirectives string

// agentgatewayConfigTemplate is agentgateway's standalone ("-f
// config.yaml") configuration: one HTTP bind whose single catch-all route
// proxies to the albedo container, with an extProc policy pointing at the
// in-process processor on the host. processingOptions mirror what the
// controller renders into the generated AgentgatewayPolicy in production
// (see internal/controller.desiredWiringPolicy) - both body phases
// enabled, since the CRS directives inspect request and response bodies.
// The two %s verbs are the ext_proc host:port and the albedo host:port.
const agentgatewayConfigTemplate = `binds:
- port: ` + gatewayPort + `
  listeners:
  - protocol: HTTP
    routes:
    - name: crs-ftw
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

// startProcessor compiles the CRS directive block into a Snapshot with a
// single catch-all route, wires matchedRulesLogPath as its
// WithMatchedRuleWriter sink (see cmd/processor's --waf-matched-rules-log,
// which this exercises the same underlying mechanism as), and serves the
// ext_proc gRPC service on an ephemeral loopback port, returning that
// port. The server is shut down via t.Cleanup.
func startProcessor(t *testing.T, logger *slog.Logger, matchedRulesLogPath string) int {
	t.Helper()

	matchedRulesFile, err := os.OpenFile(matchedRulesLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err, "failed to open matched-rules log file")
	t.Cleanup(func() { _ = matchedRulesFile.Close() })

	cfg := &config.Config{
		Directives: map[string]string{engineKey: crsFTWDirectives},
		Routes: []config.Route{{
			Host:       "*",
			PathPrefix: "/",
			WAF:        &config.WAFRef{EngineKey: engineKey},
		}},
	}
	require.NoError(t, config.Validate(cfg))

	snapshot, err := config.Compile(cfg, logger, config.WithMatchedRuleWriter(matchedRulesFile))
	require.NoError(t, err, "failed to compile the CRS regression suite's directives")

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

// ftwCorpusCacheDir is where downloaded/extracted CRS test corpora are
// cached, keyed by version, relative to this package's directory (see
// embeddedCRSVersion's doc comment: "go test" always runs with the
// package directory as its working directory). It lives inside the
// checkout rather than the OS user cache dir, gitignored, the same as
// bin/ and .envtest/ - so deleting the checkout (or a plain
// `git clean -xdf`) leaves nothing behind on the host.
const ftwCorpusCacheDir = ".corpus-cache"

// downloadCRSTestCorpus fetches and extracts the CRS project's own
// regression test corpus (tests/regression/tests/*.yaml - the actual
// attack/benign test cases go-ftw runs) for version (e.g. "v4.25.0") from
// its GitHub release tarball, and returns the extracted tests directory.
//
// This is deliberately not the vendored github.com/corazawaf/coraza-coreruleset
// module: that module embeds the *rules* (@owasp_crs/*.conf, what
// Compile's rootFS resolves Include directives against - see compile.go),
// not the test corpus that exercises them. The two must still be the
// exact same CRS release, which is why the caller always passes
// config.EmbeddedCRSVersion() rather than a hardcoded version - the corpus
// can never silently drift from the rules actually being tested.
//
// Downloads are cached under ftwCorpusCacheDir, keyed by version, so
// repeated local runs don't re-fetch ~10MB every time. Extraction targets
// a temporary sibling directory first, then os.Rename's it into place
// (atomic on the same filesystem) - so a test killed mid-extraction can
// never leave a partial cache entry that a later run mistakes for a
// complete one.
func downloadCRSTestCorpus(t *testing.T, version string) string {
	t.Helper()

	versionDir := filepath.Join(ftwCorpusCacheDir, "coreruleset-"+version)

	if testsDir := findExtractedTestsDir(t, versionDir); testsDir != "" {
		return testsDir
	}

	url := fmt.Sprintf("https://github.com/coreruleset/coreruleset/archive/refs/tags/%s.tar.gz", version)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "failed to download CRS test corpus from %s", url)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status downloading %s", url)

	require.NoError(t, os.MkdirAll(ftwCorpusCacheDir, 0o755))
	// Deliberately os.MkdirTemp under ftwCorpusCacheDir rather than
	// t.TempDir(): the staging dir must be on the same filesystem as
	// versionDir for the os.Rename below to be atomic - t.TempDir() lives
	// under the OS temp dir, which is frequently a different filesystem
	// (e.g. tmpfs) than the checkout.
	stagingDir, err := os.MkdirTemp(ftwCorpusCacheDir, "coreruleset-"+version+"-*") //nolint:usetesting // see comment above
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(stagingDir) })

	require.NoError(t, extractTarGz(resp.Body, stagingDir), "failed to extract CRS test corpus tarball")

	require.NoError(t, os.RemoveAll(versionDir), "failed to clear stale corpus cache entry")
	require.NoError(t, os.Rename(stagingDir, versionDir), "failed to move extracted corpus into place")

	testsDir := findExtractedTestsDir(t, versionDir)
	require.NotEmpty(t, testsDir, "extracted corpus is missing the expected coreruleset-*/tests/regression/tests directory")

	return testsDir
}

// findExtractedTestsDir looks for the single tests/regression/tests
// directory inside versionDir's extracted "<repo>-<version>/" top-level
// directory (GitHub's release tarballs always wrap everything in one -
// extractTarGz preserves it rather than stripping it, since this is the
// only place that needs to know where it ends up). Returns "" if it
// isn't there (or isn't unique) yet - an empty path is never itself a
// valid result, so it doubles as the "not found" signal.
func findExtractedTestsDir(t *testing.T, versionDir string) string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(versionDir, "*", "tests", "regression", "tests"))
	require.NoError(t, err)

	if len(matches) != 1 {
		return ""
	}

	info, err := os.Stat(matches[0])
	if err != nil || !info.IsDir() {
		return ""
	}

	return matches[0]
}

// extractTarGz extracts the gzip-compressed tar stream r into destDir
// verbatim, including whatever top-level directory the archive itself
// wraps everything in (see findExtractedTestsDir) - destDir is confined
// to via os.Root, so a maliciously crafted entry name can't write outside
// it.
func extractTarGz(r io.Reader, destDir string) error {
	root, err := os.OpenRoot(destDir)
	if err != nil {
		return fmt.Errorf("failed to open destination directory: %w", err)
	}
	defer root.Close()

	gzr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("failed to open gzip stream: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		// tar directory entries carry a trailing slash (e.g.
		// "coreruleset-4.25.0/"); filepath.Clean drops it (and
		// normalizes away any "./" noise) before it reaches os.Root,
		// which - unlike os.MkdirAll - doesn't tolerate one.
		name := filepath.Clean(filepath.FromSlash(header.Name))

		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", name, err)
			}
		case tar.TypeReg:
			if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", name, err)
			}

			f, err := root.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode&0o777))
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", name, err)
			}

			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("failed to write file %s: %w", name, err)
			}
			f.Close()
		default:
			// Symlinks and other special entry types don't occur in
			// CRS's release tarballs; skip anything unexpected rather
			// than failing the whole extraction.
		}
	}

	return nil
}

// ftwConfig is the subset of go-ftw's own configuration schema (see
// github.com/coreruleset/go-ftw/v2/config.FTWConfiguration) this harness
// needs to generate at runtime, since the containers' mapped ports are
// only known once they're started. Tagged with `json`, not `yaml`:
// sigs.k8s.io/yaml marshals by converting to JSON first and then to YAML,
// so it honors json struct tags rather than defining its own.
type ftwConfig struct {
	LogFile          string       `json:"logfile"`
	MaxMarkerRetries int          `json:"maxmarkerretries"`
	TestOverride     ftwTestInput `json:"testoverride"`
}

type ftwTestInput struct {
	Input ftwInputOverride `json:"input"`
}

// ftwInputOverride sets only dest_addr/port: the TCP destination every
// test's request is actually sent to, independent of whatever Host the
// test itself declares. Deliberately not setting headers/virtual_host_mode
// (see this package's doc comment) - every test's own Host header (or
// lack of one) reaches agentgateway/the processor exactly as the CRS
// authors wrote it, since both use a catch-all route with no per-host
// selection to satisfy.
type ftwInputOverride struct {
	DestAddr string `json:"dest_addr"`
	Port     int    `json:"port"`
}

// writeFTWConfig generates go-ftw's config file (see ftwConfig) pointing
// at the given matched-rules log file and gateway endpoint, and returns
// its path.
func writeFTWConfig(t *testing.T, matchedRulesLogPath, gatewayHost string, gatewayPort int) string {
	t.Helper()

	cfg := ftwConfig{
		LogFile:          matchedRulesLogPath,
		MaxMarkerRetries: 10,
		TestOverride: ftwTestInput{
			Input: ftwInputOverride{
				DestAddr: gatewayHost,
				Port:     gatewayPort,
			},
		},
	}

	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "ftw.yml")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	return path
}

// runGoFTW execs `go run` for the pinned go-ftw release (see
// goFtwModule/goFtwVersion) against corpusDir, streaming its output into
// the test log, honoring FTW_INCLUDE/FTW_FAILFAST from the environment for
// fast local triage (e.g. `FTW_INCLUDE=920100 make test-ftw`), and failing
// the test on a non-zero exit code.
func runGoFTW(t *testing.T, corpusDir, ftwConfigPath, overridesPath string) {
	t.Helper()

	args := []string{
		"run", goFtwModule + "@" + goFtwVersion,
		"run",
		"-d", corpusDir,
		"--config", ftwConfigPath,
		"--overrides", overridesPath,
		"--read-timeout=10s",
	}

	if include := os.Getenv("FTW_INCLUDE"); include != "" {
		args = append(args, "--include", include)
	}
	if os.Getenv("FTW_FAILFAST") != "" {
		args = append(args, "--fail-fast")
	}

	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	require.NoError(t, err, "go-ftw reported test failures (see output above)")
}

// embeddedCRSVersion returns the version of the OWASP Core Rule Set this
// module actually depends on (github.com/corazawaf/coraza-coreruleset/v4
// in go.mod), by parsing go.mod directly rather than via
// config.EmbeddedCRSVersion: that helper reads
// runtime/debug.ReadBuildInfo, which only populates the full dependency
// graph for binaries built with "go build" - a "go test" binary (this one)
// always reports zero Deps, so it can never resolve the module version.
// Parsing go.mod directly still keeps the corpus version self-syncing
// (the whole point - see downloadCRSTestCorpus's doc comment): it can
// never silently drift from the rules actually compiled into the
// processor under test, it just can't be read from within the running
// test binary.
func embeddedCRSVersion(t *testing.T) string {
	t.Helper()

	// This package (test/ftw) is two directories below the module root,
	// and "go test" always runs with the package directory as its
	// working directory.
	data, err := os.ReadFile("../../go.mod")
	require.NoError(t, err, "failed to read go.mod to determine the embedded CRS version")

	modFile, err := modfile.Parse("go.mod", data, nil)
	require.NoError(t, err, "failed to parse go.mod")

	for _, req := range modFile.Require {
		if req.Mod.Path == crsCoreRuleSetModulePath {
			return req.Mod.Version
		}
	}

	t.Fatalf("go.mod does not require %s", crsCoreRuleSetModulePath)

	return ""
}

// TestCRSRegression runs the OWASP Core Rule Set's own regression suite
// against gateway-protector's processor, fronted by a real agentgateway
// instance - see this package's doc comment for the full rationale and
// topology.
func TestCRSRegression(t *testing.T) {
	ctx := context.Background()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	crsVersion := embeddedCRSVersion(t)

	corpusDir := downloadCRSTestCorpus(t, crsVersion)

	matchedRulesLogPath := filepath.Join(t.TempDir(), "matched-rules.log")
	processorPort := startProcessor(t, logger, matchedRulesLogPath)

	testNetwork, err := network.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		if removeErr := testNetwork.Remove(context.Background()); removeErr != nil {
			t.Logf("failed to remove test network: %v", removeErr)
		}
	})

	albedo, err := testcontainers.Run(ctx,
		albedoImage,
		testcontainers.WithEnv(map[string]string{"MAX_BODY_SIZE": albedoMaxBodySize}),
		network.WithNetwork([]string{"albedo"}, testNetwork),
		testcontainers.WithExposedPorts(albedoPort+"/tcp"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort(albedoPort+"/tcp")),
	)
	testcontainers.CleanupContainer(t, albedo)
	require.NoError(t, err, "failed to start albedo")

	gatewayConfig := fmt.Sprintf(agentgatewayConfigTemplate,
		net.JoinHostPort(testcontainers.HostInternal, strconv.Itoa(processorPort)),
		"albedo:"+albedoPort)
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

	gatewayHost, err := gateway.Host(ctx)
	require.NoError(t, err)

	gatewayMappedPort, err := gateway.MappedPort(ctx, gatewayPort+"/tcp")
	require.NoError(t, err)

	ftwConfigPath := writeFTWConfig(t, matchedRulesLogPath, gatewayHost, int(gatewayMappedPort.Num()))

	runGoFTW(t, corpusDir, ftwConfigPath, "testdata/overrides.yml")
}
