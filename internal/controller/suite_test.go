package controller

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gwpv1alpha1 "github.com/kubewarden/gateway-protector/api/v1alpha1"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

// processorConfigMapNamespace is the namespace ProcessorConfigReconciler's
// ConfigMapPublisher is configured with for this test suite (standing in
// for the controller's own namespace, resolved from POD_NAMESPACE in
// production - see cmd/controller/main.go's podNamespace).
const processorConfigMapNamespace = "default"

var (
	cancel    context.CancelFunc
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
	mgr       manager.Manager

	// publishedConfigs records every processor config
	// ProcessorConfigReconciler publishes during this test suite (see
	// recordingPublisher), so specs can assert on what was published
	// without coupling to how (ConfigMap today, possibly a future gRPC
	// stream) - see processor_config_reconciler_test.go's
	// publishedConfig.
	publishedConfigs *recordingPublisher
)

// recordingPublisher decorates a real ConfigPublisher, remembering the
// most recently published config alongside actually publishing it through
// delegate. This lets envtest specs assert on what the reconciler decided
// to publish (routes, engine keys, directives) independently of the
// transport, while still exercising and covering the real publisher (see
// processor_config_reconciler_test.go for the one spec that does assert on
// the ConfigMap transport itself).
type recordingPublisher struct {
	delegate ConfigPublisher

	mu   sync.Mutex
	last *procconfig.Config
}

func (p *recordingPublisher) Publish(ctx context.Context, cfg *procconfig.Config) error {
	p.mu.Lock()
	p.last = cfg
	p.mu.Unlock()

	return p.delegate.Publish(ctx, cfg)
}

// lastConfig returns the most recently published config, or nil if none
// has been published yet.
func (p *recordingPublisher) lastConfig() *procconfig.Config {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.last
}

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	var ctx context.Context
	ctx, cancel = context.WithCancel(context.TODO())

	var err error
	err = gwpv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = gatewayv1.Install(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "charts", "gateway-protector", "templates", "crd"),
			gatewayAPICRDDirectory(),
		},
		ErrorIfCRDPathMissing: true,
	}

	// Retrieve the first found binary directory to allow running tests from IDEs
	if getFirstFoundEnvTestBinaryDir() != "" {
		testEnv.BinaryAssetsDirectory = getFirstFoundEnvTestBinaryDir()
	}

	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	mgr, err = ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme.Scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache:   CacheOptions(),
	})
	Expect(err).NotTo(HaveOccurred())

	err = (&WAFPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	publishedConfigs = &recordingPublisher{
		delegate: &ConfigMapPublisher{
			Client:    mgr.GetClient(),
			Namespace: processorConfigMapNamespace,
		},
	}

	err = (&ProcessorConfigReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Publisher: publishedConfigs,
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err := mgr.Start(ctx)
		Expect(err).NotTo(HaveOccurred(), "failed to run manager")
	}()
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	cancel()
	Eventually(func() error {
		return testEnv.Stop()
	}, time.Minute, time.Second).Should(Succeed())
})

// getFirstFoundEnvTestBinaryDir locates the first binary in the specified path.
// ENVTEST-based tests depend on specific binaries, usually located in paths set by
// controller-runtime. When running tests directly (e.g., via an IDE) without using
// Makefile targets, the 'BinaryAssetsDirectory' must be explicitly configured.
//
// This function streamlines the process by finding the required binaries, similar to
// setting the 'KUBEBUILDER_ASSETS' environment variable. To ensure the binaries are
// properly set up, run 'make setup-envtest' beforehand.
func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		logf.Log.Error(err, "Failed to read directory", "path", basePath)
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}

// gatewayAPICRDDirectory resolves the on-disk directory containing the
// standard Gateway API CRDs (Gateway, HTTPRoute, etc.) shipped inside the
// sigs.k8s.io/gateway-api module that this repository already depends on
// (see go.mod), so envtest installs a version that always matches the Go
// types compiled into the reconciler - no vendored copy to keep in sync.
func gatewayAPICRDDirectory() string {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "sigs.k8s.io/gateway-api").Output()
	Expect(err).NotTo(HaveOccurred(), "failed to resolve sigs.k8s.io/gateway-api module directory")

	return filepath.Join(strings.TrimSpace(string(out)), "config", "crd", "standard")
}
