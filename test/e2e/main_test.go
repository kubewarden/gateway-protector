// Package e2e exercises gateway-protector end-to-end: it stands up a real
// Kind cluster, installs the Gateway API CRDs, agentgateway (the data plane
// this project generates AgentgatewayPolicy objects for) and this repo's
// own Helm chart, then drives the cluster through sigs.k8s.io/e2e-framework
// features/assessments. Modeled after
// https://github.com/kubewarden/sbomscanner/tree/main/test/e2e.
package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kubewarden/gateway-protector/api/v1alpha1"
	"github.com/kubewarden/gateway-protector/internal/agentgatewayapi"
)

var (
	testenv         env.Environment
	kindClusterName string

	// namespace is where the Helm chart (and this controller) live.
	namespace       = "gateway-protector-system"
	controllerImage = "ghcr.io/kubewarden/gateway-protector/controller:latest"
	processorImage  = "ghcr.io/kubewarden/gateway-protector/processor:latest"
	releaseName     = "gateway-protector"
	chartPath       = "../../charts/gateway-protector"

	// agentgatewayVersion is pinned to match the Tiltfile, so the installed
	// control plane matches what this test suite was written against. The
	// Gateway API version comes from go.mod instead, see gatewayAPIVersion.
	agentgatewayVersion = "v1.7.0"
	agentgatewayNS      = "agentgateway-system"
)

// gatewayAPIVersion returns the version of sigs.k8s.io/gateway-api in
// go.mod, so the installed CRDs match the Go types compiled into the
// controller. The envtest suite does the same, see
// internal/controller/suite_test.go.
func gatewayAPIVersion(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Version}}", "sigs.k8s.io/gateway-api").Output()
	if err != nil {
		return "", fmt.Errorf("failed to read the sigs.k8s.io/gateway-api version from go.mod: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func TestMain(m *testing.M) {
	cfg, _ := envconf.NewFromFlags()
	testenv = env.NewWithConfig(cfg)
	kindClusterName = envconf.RandomName("gateway-protector-e2e-cluster", 32)

	testenv.Setup(
		envfuncs.CreateCluster(kind.NewProvider(), kindClusterName),
		envfuncs.CreateNamespace(namespace),
		envfuncs.LoadImageToCluster(kindClusterName, controllerImage, "--verbose", "--mode", "direct"),
		envfuncs.LoadImageToCluster(kindClusterName, processorImage, "--verbose", "--mode", "direct"),
		func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
			// Gateway API CRDs (Gateway, HTTPRoute, ...) that both
			// agentgateway and this project's WAFPolicy/WAFRuleSet CRDs
			// build on. Server-side apply is required for the Gateway API's
			// own CRDs (see the Tiltfile for the same requirement).
			version, err := gatewayAPIVersion(ctx)
			if err != nil {
				return ctx, err
			}
			url := fmt.Sprintf("https://github.com/kubernetes-sigs/gateway-api/releases/download/%s/standard-install.yaml", version)
			if err = decoder.DecodeURL(ctx, url, decoder.CreateHandler(cfg.Client().Resources())); err != nil {
				return ctx, fmt.Errorf("failed to install Gateway API CRDs: %w", err)
			}

			return ctx, nil
		},
		func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
			manager := helm.New(cfg.KubeconfigFile())

			// agentgateway: the data plane this controller generates
			// AgentgatewayPolicy objects for. Installed from its own OCI
			// registry, mirroring the Tiltfile.
			err := manager.RunInstall(
				helm.WithName("agentgateway-crds"),
				helm.WithChart("oci://cr.agentgateway.dev/charts/agentgateway-crds"),
				helm.WithNamespace(agentgatewayNS),
				helm.WithArgs("--create-namespace", "--version", agentgatewayVersion),
				helm.WithWait(),
				helm.WithTimeout("3m"))
			if err != nil {
				return ctx, fmt.Errorf("failed to install agentgateway-crds: %w", err)
			}

			err = manager.RunInstall(
				helm.WithName("agentgateway"),
				helm.WithChart("oci://cr.agentgateway.dev/charts/agentgateway"),
				helm.WithNamespace(agentgatewayNS),
				helm.WithArgs("--version", agentgatewayVersion),
				helm.WithWait(),
				helm.WithTimeout("3m"))
			if err != nil {
				return ctx, fmt.Errorf("failed to install agentgateway: %w", err)
			}

			// gateway-protector itself, from the local chart.
			err = manager.RunInstall(helm.WithName(releaseName),
				helm.WithNamespace(namespace),
				helm.WithChart(chartPath),
				helm.WithWait(),
				helm.WithArgs(
					"--set", "controller.image.tag=latest",
					"--set", "processor.image.tag=latest",
					"--set", "processor.logLevel=debug",
				),
				helm.WithTimeout("3m"))
			if err != nil {
				return ctx, fmt.Errorf("failed to install gateway-protector: %w", err)
			}

			// Register schemes so tests can CRUD typed objects directly.
			scheme := cfg.Client().Resources().GetScheme()
			if err := v1alpha1.AddToScheme(scheme); err != nil {
				return ctx, fmt.Errorf("failed to add gateway-protector v1alpha1 scheme: %w", err)
			}
			if err := gatewayv1.Install(scheme); err != nil {
				return ctx, fmt.Errorf("failed to add gateway-api v1 scheme: %w", err)
			}
			if err := agentgatewayapi.AddToScheme(scheme); err != nil {
				return ctx, fmt.Errorf("failed to add agentgatewayapi scheme: %w", err)
			}

			return ctx, nil
		},
	)

	testenv.Finish(
		func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
			manager := helm.New(cfg.KubeconfigFile())
			if err := manager.RunUninstall(helm.WithName(releaseName), helm.WithNamespace(namespace)); err != nil {
				return ctx, fmt.Errorf("failed to uninstall gateway-protector: %w", err)
			}

			return ctx, nil
		},
		envfuncs.ExportClusterLogs(kindClusterName, "./logs"),
		envfuncs.DestroyCluster(kindClusterName),
	)

	os.Exit(testenv.Run(m))
}
