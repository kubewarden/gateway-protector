package controller

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

// ProcessorConfigMapName is the name of the ConfigMap the controller
// publishes the processor's data-plane configuration to. It is
// deliberately a fixed name rather than something derived from the Helm
// release: the controller owns exactly one processor config per
// installation of this operator into a namespace, so there is nothing for
// a user to configure here (unlike, say, the release name), and hardcoding
// it means both this reconciler and the chart-rendered processor
// Deployment (which mounts this same ConfigMap) can refer to it without
// threading a value through Helm.
const ProcessorConfigMapName = "gateway-protector-processor-config"

// processorConfigMapDataKey is the key under ConfigMap.data holding the
// YAML-encoded procconfig.Config - see docs/processor.md for the schema
// and cmd/processor's --config flag, which points at this same key mounted
// as a file.
const processorConfigMapDataKey = "config.yaml"

// ConfigPublisher hands the compiled processor configuration to the data
// plane. ConfigMapPublisher is the only implementation today (ConfigMap +
// the processor's own fsnotify watch - see
// internal/processor/config.Watcher); a future gRPC config stream (see
// docs, "production" distribution) would satisfy the same interface,
// letting ProcessorConfigReconciler stay unchanged.
type ConfigPublisher interface {
	Publish(ctx context.Context, cfg *procconfig.Config) error
}

// ConfigMapPublisher publishes the processor configuration by
// creating/updating a ConfigMap (name: ProcessorConfigMapName) in
// Namespace - the same namespace this controller itself runs in, which is
// also where the chart deploys the processor Deployment that mounts it.
type ConfigMapPublisher struct {
	Client    client.Client
	Namespace string
}

var _ ConfigPublisher = &ConfigMapPublisher{}

// Publish renders cfg as YAML and creates/updates the ConfigMap, skipping
// the API call entirely when the content is already up to date (see
// controllerutil.CreateOrUpdate).
func (p *ConfigMapPublisher) Publish(ctx context.Context, cfg *procconfig.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal processor config: %w", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ProcessorConfigMapName,
			Namespace: p.Namespace,
		},
	}

	result, err := controllerutil.CreateOrUpdate(ctx, p.Client, cm, func() error {
		if cm.Data == nil {
			cm.Data = make(map[string]string, 1)
		}

		cm.Data[processorConfigMapDataKey] = string(data)

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create/update ConfigMap %s/%s: %w", p.Namespace, ProcessorConfigMapName, err)
	}

	if result != controllerutil.OperationResultNone {
		logf.FromContext(ctx).Info("Published processor config", "configMap", ProcessorConfigMapName, "operation", result)
	}

	return nil
}
