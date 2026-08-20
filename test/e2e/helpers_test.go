package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

const (
	// httpbinGatewayName/httpbinRouteName/httpbinDeploymentName mirror
	// test/manifests/httpbin.yaml, shared with the Tiltfile. The
	// manifest's own namespace ("httpbin") is only used by
	// TestWAFPolicyGatewayLifecycle; every other e2e test deploys the same
	// manifest into its own dedicated namespace (see deployHTTPBinBase) so
	// tests never interfere with each other regardless of execution
	// order.
	httpbinGatewayName    = "httpbin-gateway"
	httpbinRouteName      = "httpbin"
	httpbinDeploymentName = "httpbin"
	curlContainerName     = "curl"

	// maliciousQuery is a classic reflected-XSS payload that OWASP CRS
	// flags at paranoia level 1 - the same one used in the Tiltfile's demo
	// instructions, percent-encoded: agentgateway's HTTP/1.1 front end
	// rejects raw "<"/">" in a request target with its own 400 before the
	// request ever reaches the processor, independently of any WAFPolicy,
	// so the literal (unencoded) form can never reach the WAF to be
	// blocked. Coraza/CRS decode percent-encoding before pattern matching,
	// so the encoded form still triggers the same rule.
	maliciousQuery = "?q=%3Cscript%3Ealert(1)%3C/script%3E"

	trafficTimeout = 2 * time.Minute
	statusTimeout  = 1 * time.Minute
)

// deployHTTPBinBase applies test/manifests/httpbin.yaml into ns - creating
// ns first if it doesn't already exist, since the manifest's own Namespace
// object is hardcoded to "httpbin" and MutateNamespace only redirects
// namespace-scoped objects (ServiceAccount/Service/Deployment/Gateway/
// HTTPRoute), not that Namespace object's own name. Every e2e test other
// than TestWAFPolicyGatewayLifecycle uses this to get a fully independent
// httpbin + Gateway + catch-all HTTPRoute stack in its own namespace, so
// tests never interfere with each other regardless of execution order.
//
// The manifest's stray literal "httpbin" Namespace object still gets
// applied as a side effect (harmless: CreateIgnoreAlreadyExists makes this
// idempotent across every test that does this).
func deployHTTPBinBase(ctx context.Context, t *testing.T, cfg *envconf.Config, ns string) {
	t.Helper()

	nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
	if err := cfg.Client().Resources().Create(ctx, nsObj); err != nil && !apierrors.IsAlreadyExists(err) {
		require.NoError(t, err, "failed to create namespace %s", ns)
	}

	err := decoder.DecodeEachFile(ctx, os.DirFS("../manifests"), "httpbin.yaml",
		decoder.CreateIgnoreAlreadyExists(cfg.Client().Resources()),
		decoder.MutateNamespace(ns),
	)
	require.NoError(t, err, "failed to apply test/manifests/httpbin.yaml into namespace %s", ns)

	err = wait.For(
		conditions.New(cfg.Client().Resources()).DeploymentAvailable(httpbinDeploymentName, ns),
		wait.WithTimeout(trafficTimeout),
	)
	require.NoError(t, err, "httpbin Deployment never became Available in %s", ns)

	// agentgateway creates a Deployment (and Service) named after the
	// Gateway object, in the Gateway's own namespace, once it has
	// programmed the Gateway.
	err = wait.For(
		conditions.New(cfg.Client().Resources()).DeploymentAvailable(httpbinGatewayName, ns),
		wait.WithTimeout(trafficTimeout),
	)
	require.NoError(t, err, "agentgateway proxy Deployment %s/%s never became Available", ns, httpbinGatewayName)
}

// curlStatus execs into httpbin's curl sidecar (kept around exactly for
// this purpose - see test/manifests/httpbin.yaml) and returns the HTTP
// status code a request through the agentgateway-managed proxy Service in
// ns gets back. An empty hostHeader uses the Service's own default Host
// (<gatewayName>.<ns>); a non-empty one overrides it, for hitting a
// non-catch-all HTTPRoute matched by hostname rather than by Service DNS
// name.
func curlStatus(ctx context.Context, cfg *envconf.Config, ns, hostHeader, path string) (string, error) {
	var stdout, stderr bytes.Buffer

	url := fmt.Sprintf("http://%s.%s/%s", httpbinGatewayName, ns, strings.TrimPrefix(path, "/"))
	cmd := []string{"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url}
	if hostHeader != "" {
		cmd = append(cmd, "-H", "Host: "+hostHeader)
	}

	err := cfg.Client().Resources().ExecInDeployment(ctx, ns, httpbinDeploymentName, cmd, &stdout, &stderr,
		resources.WithDeploymentContainerName(curlContainerName))
	if err != nil {
		return "", fmt.Errorf("curl exec failed: %w (stderr: %s)", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

// curlPost is curlStatus's POST-with-body counterpart: it execs into
// httpbin's curl sidecar and returns both the HTTP status code and the
// full response body, for tests that need to inspect what came back (e.g.
// to verify the request/response body itself wasn't mangled in transit -
// see waitForPostBodyEcho). The status code is appended by curl's -w as a
// trailing line, then split off.
func curlPost(ctx context.Context, cfg *envconf.Config, ns, path, contentType, body string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	url := fmt.Sprintf("http://%s.%s/%s", httpbinGatewayName, ns, strings.TrimPrefix(path, "/"))
	cmd := []string{
		"curl", "-s", "-X", "POST",
		"-H", "Content-Type: " + contentType,
		"--data-raw", body,
		"-w", "\n%{http_code}",
		url,
	}

	if execErr := cfg.Client().Resources().ExecInDeployment(ctx, ns, httpbinDeploymentName, cmd, &stdout, &stderr,
		resources.WithDeploymentContainerName(curlContainerName)); execErr != nil {
		return "", "", fmt.Errorf("curl exec failed: %w (stderr: %s)", execErr, stderr.String())
	}

	output := stdout.String()

	idx := strings.LastIndex(output, "\n")
	if idx == -1 {
		return "", "", fmt.Errorf("unexpected curl output (missing status line): %q", output)
	}

	return strings.TrimSpace(output[idx+1:]), output[:idx], nil
}

// waitForStatus polls curlStatus until it returns want or timeout elapses.
func waitForStatus(ctx context.Context, t *testing.T, cfg *envconf.Config, ns, hostHeader, path, want string, timeout time.Duration) {
	t.Helper()

	var last string
	err := wait.For(func(ctx context.Context) (bool, error) {
		status, err := curlStatus(ctx, cfg, ns, hostHeader, path)
		if err != nil {
			// The gateway/pod may not be reachable yet right after
			// creation - keep polling instead of failing fast.
			return false, nil //nolint:nilerr // transient exec error, keep polling until timeout
		}

		last = status

		return status == want, nil
	}, wait.WithTimeout(timeout), wait.WithInterval(5*time.Second), wait.WithContext(ctx))
	require.NoError(t, err, "timed out waiting for %s (Host: %q) to return %s (last status observed: %q)", path, hostHeader, want, last)
}

// waitForPostBodyEcho POSTs body (as contentType) to path repeatedly until
// it gets back a 200 whose response echoes body back byte-for-byte in
// go-httpbin's "data" JSON field, or times out.
//
// This is a body-integrity check, not just a status-code one: agentgateway's
// FULL_DUPLEX_STREAMED ext_proc mode rebuilds both the request body (before
// it reaches httpbin) and the response body (before it reaches the client)
// exclusively from the chunks the processor echoes back - a processor that
// silently stopped echoing, or never released chunks it was holding
// pending a WAF verdict, would still answer every ext_proc message and
// every status-code assertion would stay green, while the body itself was
// truncated to nothing. See internal/processor/responses.go's
// echoRequestBody/echoResponseBody and test/coraza-e2e for where exactly
// this failure mode was first caught.
func waitForPostBodyEcho(ctx context.Context, t *testing.T, cfg *envconf.Config, ns, path, contentType, body string, timeout time.Duration) {
	t.Helper()

	var lastStatus, lastBody string
	err := wait.For(func(ctx context.Context) (bool, error) {
		status, respBody, err := curlPost(ctx, cfg, ns, path, contentType, body)
		if err != nil {
			// The gateway/pod may not be reachable yet right after
			// creation - keep polling instead of failing fast.
			return false, nil //nolint:nilerr // transient exec error, keep polling until timeout
		}

		lastStatus, lastBody = status, respBody
		if status != "200" {
			return false, nil
		}

		var echoed struct {
			Data string `json:"data"`
		}
		if jsonErr := json.Unmarshal([]byte(respBody), &echoed); jsonErr != nil {
			return false, nil //nolint:nilerr // transient/partial response, keep polling until timeout
		}

		return echoed.Data == body, nil
	}, wait.WithTimeout(timeout), wait.WithInterval(5*time.Second), wait.WithContext(ctx))
	require.NoError(t, err, "timed out waiting for %s to echo the posted body unmodified "+
		"(request/response body may have been truncated - last status %q, last response body %q)",
		path, lastStatus, lastBody)
}
