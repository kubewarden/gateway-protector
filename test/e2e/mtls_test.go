package e2e

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

// processorReadyMTLSFields are the boolean fields cmd/processor/main.go's
// "Processor ready" startup log line carries for each of the two mTLS
// connections it can secure - see internal/certs and docs/processor.md's
// "Config stream"/"ext_proc mTLS" sections.
//
// Asserting on these (rather than only on WAF traffic behavior, already
// covered by every other e2e test) is what actually proves both
// connections were negotiated with TLS, not merely that they still work:
// agentgateway's ext_proc integration fails closed (see
// docs/agentgateway-extproc.md), so a *broken* mTLS handshake already
// fails every traffic assertion on its own - but a regression that
// silently disabled mTLS on both ends of a connection (falling back to a
// still-working plaintext connection) would pass every other e2e
// assertion unnoticed. Only this test would catch that.
var processorReadyMTLSFields = []string{`"config-stream-mtls":true`, `"ext-proc-mtls":true`}

// TestProcessorMTLSEnabled asserts the processor logs confirm it actually
// negotiated TLS on both connections the chart's default install secures
// with mTLS: the config stream to the controller, and the ext_proc
// connection from agentgateway. It reads the processor pod's own startup
// log line rather than inspecting Secret/ConfigMap content, so it
// exercises the real, running process's own view of its configuration.
func TestProcessorMTLSEnabled(t *testing.T) {
	f := features.New("Processor mTLS").
		Assess("processor logs confirm both mTLS connections are enabled", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			clientset, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
			require.NoError(t, err, "failed to build a Kubernetes clientset")

			pod := findProcessorPod(ctx, t, cfg)

			var logs string
			err = wait.For(func(ctx context.Context) (bool, error) {
				var fetchErr error
				logs, fetchErr = fetchPodLogs(ctx, clientset, namespace, pod, "processor")
				if fetchErr != nil {
					// Transient (e.g. pod not ready to serve logs yet) - keep polling until timeout.
					return false, nil //nolint:nilerr // transient error, keep polling until timeout
				}

				return strings.Contains(logs, "Processor ready"), nil
			}, wait.WithTimeout(statusTimeout), wait.WithInterval(5*time.Second), wait.WithContext(ctx))
			require.NoError(t, err, "processor pod %s/%s never logged its startup line", namespace, pod)

			for _, field := range processorReadyMTLSFields {
				assert.Contains(t, logs, field,
					"processor startup log missing %s - see cmd/processor/main.go's \"Processor ready\" log line", field)
			}

			return ctx
		})

	testenv.Test(t, f.Feature())
}

// findProcessorPod returns the name of the (single-replica, by chart
// default) processor Pod in namespace.
func findProcessorPod(ctx context.Context, t *testing.T, cfg *envconf.Config) string {
	t.Helper()

	var pods corev1.PodList
	err := cfg.Client().Resources(namespace).List(ctx, &pods, resources.WithLabelSelector("app.kubernetes.io/component=processor"))
	require.NoError(t, err, "failed to list processor pods in namespace %s", namespace)
	require.NotEmpty(t, pods.Items, "no processor pod found in namespace %s", namespace)

	return pods.Items[0].Name
}

// fetchPodLogs returns the full current logs of container in namespace/pod.
func fetchPodLogs(ctx context.Context, clientset *kubernetes.Clientset, namespace, pod, container string) (string, error) {
	stream, err := clientset.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: container}).Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to open log stream for %s/%s: %w", namespace, pod, err)
	}
	defer stream.Close()

	data, err := io.ReadAll(stream)
	if err != nil {
		return "", fmt.Errorf("failed to read logs for %s/%s: %w", namespace, pod, err)
	}

	return string(data), nil
}
