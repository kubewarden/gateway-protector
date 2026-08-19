package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/gateway-protector/internal/certs"
)

// CertReconciler is a manager.Runnable (not a watch-based reconciler) that
// periodically checks the CA and the leaf certificates used for mTLS -
// the controller's config-stream server cert, the processor's config-stream
// client cert, the processor's ext_proc server cert, and agentgateway's
// ext_proc client cert - rotating whatever is within RotationLookahead of
// expiring.
//
// This mirrors kubewarden's admission-controller CertReconciler
// (github.com/kubewarden/adm-controller/internal/controller), with one
// difference: instead of patching a webhook's CABundle, it keeps each leaf
// Secret's own CA-bundle key (certs.CABundleKey) up to date, plus a
// CA-bundle ConfigMap (certs.CABundleConfigMapName) for agentgateway,
// which only reads trust bundles from ConfigMaps.
type CertReconciler struct {
	client.Client

	Log       logr.Logger
	Namespace string
}

var _ interface {
	Start(context.Context) error
	NeedLeaderElection() bool
} = &CertReconciler{}

// Start begins the periodic reconciler. Implements manager.Runnable.
func (r *CertReconciler) Start(ctx context.Context) error {
	r.Log.Info("Starting cert reconciler ticker")

	ticker := time.NewTicker(certs.ReconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.Log.Info("Stopping cert reconciler")
			return nil
		case <-ticker.C:
			if err := r.reconcile(ctx); err != nil {
				r.Log.Error(err, "Failed to reconcile certificates")
			}
		}
	}
}

// NeedLeaderElection returns true: only the leader should generate/rotate
// certificates. Implements manager.LeaderElectionRunnable.
func (r *CertReconciler) NeedLeaderElection() bool {
	return true
}

// SetupWithManager registers the reconciler with mgr as a Runnable.
func (r *CertReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("failed enrolling cert reconciler with manager: %w", err)
	}

	return nil
}

// reconcile rotates the CA (if due), drops the previous CA once it has
// expired, rotates every leaf certificate (if due, or if signed by a CA
// no longer current) - refreshing each leaf Secret's CA-bundle key along
// the way - and keeps the CA-bundle ConfigMap in sync.
func (r *CertReconciler) reconcile(ctx context.Context) error {
	caSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: certs.CASecretName, Namespace: r.Namespace}, caSecret); err != nil {
		return fmt.Errorf("failed to get CA secret: %w", err)
	}

	if err := r.reconcileCA(ctx, caSecret); err != nil {
		return fmt.Errorf("failed to reconcile CA: %w", err)
	}
	if err := r.reconcileOldCA(ctx, caSecret); err != nil {
		return fmt.Errorf("failed to reconcile old CA: %w", err)
	}

	caCert, _, err := certs.ExtractCA(caSecret)
	if err != nil {
		return fmt.Errorf("failed to extract CA from secret: %w", err)
	}
	caBundle := append(append([]byte{}, caCert...), caSecret.Data[certs.OldCACertKey]...)

	if err := r.reconcileCABundleConfigMap(ctx, caBundle); err != nil {
		return fmt.Errorf("failed to reconcile CA bundle configmap: %w", err)
	}

	for _, leaf := range []struct {
		secretName string
		dnsName    string
	}{
		{certs.ControllerCertSecretName, certs.ControllerServerDNSName + "." + r.Namespace + ".svc"},
		{certs.ProcessorClientCertSecretName, certs.ProcessorClientCommonName},
		{certs.ProcessorServerCertSecretName, certs.DNSName(certs.ProcessorServerServiceName, r.Namespace)},
		{certs.AgentgatewayClientCertSecretName, certs.AgentgatewayClientCommonName},
	} {
		leafSecret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: leaf.secretName, Namespace: r.Namespace}, leafSecret); err != nil {
			return fmt.Errorf("failed to get leaf cert secret %q: %w", leaf.secretName, err)
		}

		if err := r.reconcileLeafCert(ctx, leafSecret, caSecret, leaf.dnsName, caBundle); err != nil {
			return fmt.Errorf("failed to reconcile leaf cert secret %q: %w", leaf.secretName, err)
		}
	}

	return nil
}

// reconcileCABundleConfigMap keeps the CA-bundle ConfigMap's data in sync
// with caBundle. Unlike the leaf Secrets (whose CA-bundle key is only one
// of several data keys touched by reconcileLeafCert), this ConfigMap
// exists solely to carry the bundle, for agentgateway's
// backend.tls.caCertificateRefs (which only accepts ConfigMaps, never
// Secrets).
func (r *CertReconciler) reconcileCABundleConfigMap(ctx context.Context, caBundle []byte) error {
	configMap := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: certs.CABundleConfigMapName, Namespace: r.Namespace}, configMap); err != nil {
		return fmt.Errorf("failed to get CA bundle configmap: %w", err)
	}

	if configMap.Data[certs.CABundleKey] == string(caBundle) {
		return nil
	}

	if configMap.Data == nil {
		configMap.Data = map[string]string{}
	}
	configMap.Data[certs.CABundleKey] = string(caBundle)
	if err := r.Update(ctx, configMap); err != nil {
		return fmt.Errorf("failed to update CA bundle configmap: %w", err)
	}

	return nil
}

// reconcileCA rotates the CA certificate if it is about to expire,
// stashing the previous certificate under OldCACertKey so leaf
// certificates it already signed keep verifying until it actually
// expires (see reconcileOldCA).
func (r *CertReconciler) reconcileCA(ctx context.Context, caSecret *corev1.Secret) error {
	caCert, caPrivateKey, err := certs.ExtractCA(caSecret)
	if err != nil {
		return fmt.Errorf("failed to extract CA from secret: %w", err)
	}

	if err := certs.VerifyCA(caCert, caPrivateKey, time.Now().Add(certs.RotationLookahead)); err != nil {
		r.Log.Info("CA certificate verification failed, rotating the CA", "verificationError", err)

		oldCACert := caCert
		newCACert, newCAPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(certs.CAExpiration))
		if err != nil {
			return fmt.Errorf("failed to generate CA cert: %w", err)
		}

		if caSecret.Data == nil {
			caSecret.Data = map[string][]byte{}
		}
		caSecret.Data[certs.CertKey] = newCACert
		caSecret.Data[certs.PrivateKeyKey] = newCAPrivateKey
		caSecret.Data[certs.OldCACertKey] = oldCACert
		if err := r.Update(ctx, caSecret); err != nil {
			return fmt.Errorf("failed to update CA secret: %w", err)
		}

		r.Log.Info("CA certificate rotated successfully")
	}

	return nil
}

// reconcileOldCA removes the stashed previous CA certificate once it is no
// longer valid at all (fully expired), so the CA bundle handed out to leaf
// Secrets eventually shrinks back down to a single certificate.
func (r *CertReconciler) reconcileOldCA(ctx context.Context, caSecret *corev1.Secret) error {
	oldCACert, ok := caSecret.Data[certs.OldCACertKey]
	if !ok {
		return nil
	}

	if err := certs.VerifyCA(oldCACert, nil, time.Now()); err != nil {
		r.Log.Info("Old CA certificate is no longer valid, removing it", "verificationError", err)

		delete(caSecret.Data, certs.OldCACertKey)
		if err := r.Update(ctx, caSecret); err != nil {
			return fmt.Errorf("failed to update CA secret: %w", err)
		}

		r.Log.Info("Old CA certificate removed successfully")
	}

	return nil
}

// reconcileLeafCert rotates a leaf certificate if it is about to expire or
// no longer verifies against the current CA (e.g. right after a CA
// rotation), and keeps its CA-bundle key in sync with caBundle regardless.
func (r *CertReconciler) reconcileLeafCert(ctx context.Context, leafSecret *corev1.Secret, caSecret *corev1.Secret, dnsName string, caBundle []byte) error {
	cert, privateKey, err := certs.ExtractLeafCert(leafSecret)
	if err != nil {
		return fmt.Errorf("failed to extract leaf cert from secret: %w", err)
	}

	caCert, caPrivateKey, err := certs.ExtractCA(caSecret)
	if err != nil {
		return fmt.Errorf("failed to extract CA from secret: %w", err)
	}

	pool, err := certs.NewCertPool(caCert)
	if err != nil {
		return fmt.Errorf("failed to create cert pool: %w", err)
	}

	updated := false

	if err := certs.VerifyCert(cert, privateKey, pool, dnsName, time.Now().Add(certs.RotationLookahead)); err != nil {
		r.Log.Info("Leaf certificate verification failed, rotating it", "dnsName", dnsName, "verificationError", err)

		newCert, newPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(certs.LeafExpiration), dnsName)
		if err != nil {
			return fmt.Errorf("failed to generate leaf cert: %w", err)
		}

		if leafSecret.Data == nil {
			leafSecret.Data = map[string][]byte{}
		}
		leafSecret.Data[certs.CertKey] = newCert
		leafSecret.Data[certs.PrivateKeyKey] = newPrivateKey
		updated = true

		r.Log.Info("Leaf certificate rotated successfully", "dnsName", dnsName)
	}

	if string(leafSecret.Data[certs.CABundleKey]) != string(caBundle) {
		leafSecret.Data[certs.CABundleKey] = caBundle
		updated = true
	}

	if updated {
		if err := r.Update(ctx, leafSecret); err != nil {
			return fmt.Errorf("failed to update leaf cert secret: %w", err)
		}
	}

	return nil
}
