package ca

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"
)

const (
	// CAConfigMapName is the ConfigMap name for the CA certificate.
	CAConfigMapName = "kloak-ca-cert"
	// CAConfigMapKey is the key within the ConfigMap for the CA cert.
	CAConfigMapKey = "ca.crt"
)

// Reconciler watches the kloak-ca Secret and updates the Provider.
// It also syncs the CA to ConfigMaps in labeled namespaces.
type Reconciler struct {
	client.Client
	Provider       *Provider
	Namespace      string // The namespace where kloak-ca Secret lives
	Log            logr.Logger
	SyncNamespaces bool // If true, sync ConfigMap to labeled namespaces
}

// Reconcile is called when the kloak-ca Secret changes.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("secret", req.NamespacedName)

	// Only reconcile the kloak-ca Secret in our namespace
	if req.Name != SecretName || req.Namespace != r.Namespace {
		return ctrl.Result{}, nil
	}

	log.Info("Reconciling CA secret")

	// Fetch the Secret
	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		if errors.IsNotFound(err) {
			log.Info("CA secret not found, waiting for creation")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("getting secret: %w", err)
	}

	// Load CA from Secret
	certPEM, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		certPEM, ok = secret.Data[CertKey]
		if !ok {
			log.Error(nil, "Secret missing CA certificate key")
			return ctrl.Result{}, nil
		}
	}
	keyPEM, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		keyPEM, ok = secret.Data[KeyKey]
		if !ok {
			log.Error(nil, "Secret missing CA key")
			return ctrl.Result{}, nil
		}
	}

	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		log.Error(err, "Failed to load CA from secret")
		return ctrl.Result{}, nil
	}

	// Update the provider
	r.Provider.Update(ca)

	// Sync ConfigMap to labeled namespaces if enabled
	if r.SyncNamespaces {
		if err := r.syncConfigMapsToNamespaces(ctx, certPEM); err != nil {
			log.Error(err, "Failed to sync ConfigMaps to namespaces")
			// Don't return error - we'll retry on next reconcile
		}
	}

	return ctrl.Result{}, nil
}

// syncConfigMapsToNamespaces creates/updates the CA ConfigMap in all namespaces
// labeled with getkloak.io/enabled=true.
func (r *Reconciler) syncConfigMapsToNamespaces(ctx context.Context, certPEM []byte) error {
	log := r.Log.WithName("configmap-sync")

	// List namespaces with the label
	namespaceList := &corev1.NamespaceList{}
	if err := r.List(ctx, namespaceList, client.MatchingLabels{
		"getkloak.io/enabled": "true",
	}); err != nil {
		return fmt.Errorf("listing namespaces: %w", err)
	}

	for _, ns := range namespaceList.Items {
		if err := r.ensureConfigMap(ctx, ns.Name, certPEM); err != nil {
			log.Error(err, "Failed to ensure ConfigMap in namespace", "namespace", ns.Name)
			// Continue with other namespaces
		}
	}

	return nil
}

// ensureConfigMap creates or updates the CA ConfigMap in the given namespace.
func (r *Reconciler) ensureConfigMap(ctx context.Context, namespace string, certPEM []byte) error {
	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Name: CAConfigMapName, Namespace: namespace}

	err := r.Get(ctx, key, cm)
	if errors.IsNotFound(err) {
		// Create new ConfigMap
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      CAConfigMapName,
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":       "kloak",
					"app.kubernetes.io/component":  "ca",
					"app.kubernetes.io/managed-by": "kloak-controller",
				},
			},
			Data: map[string]string{
				CAConfigMapKey: string(certPEM),
			},
		}
		if err := r.Create(ctx, cm); err != nil {
			return fmt.Errorf("creating ConfigMap: %w", err)
		}
		r.Log.Info("Created CA ConfigMap", "namespace", namespace)
		return nil
	} else if err != nil {
		return fmt.Errorf("getting ConfigMap: %w", err)
	}

	// Update existing ConfigMap if data differs
	if cm.Data[CAConfigMapKey] != string(certPEM) {
		cm.Data[CAConfigMapKey] = string(certPEM)
		if err := r.Update(ctx, cm); err != nil {
			return fmt.Errorf("updating ConfigMap: %w", err)
		}
		r.Log.Info("Updated CA ConfigMap", "namespace", namespace)
	}

	return nil
}

// SetupWithManager registers the reconciler with the manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Use a predicate to only watch the kloak-ca secret
	secretPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetName() == SecretName && obj.GetNamespace() == r.Namespace
	})

	// Use a predicate to only watch labeled namespaces
	nsPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetLabels()["getkloak.io/enabled"] == "true"
	})

	return ctrl.NewControllerManagedBy(mgr).
		Named("ca-reconciler").
		// Watch only the kloak-ca Secret with predicate
		For(&corev1.Secret{}, builder.WithPredicates(secretPredicate)).
		// Watch namespaces with label predicate
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				// Trigger reconcile of the CA secret when a namespace is labeled
				return []reconcile.Request{{
					NamespacedName: types.NamespacedName{
						Name:      SecretName,
						Namespace: r.Namespace,
					},
				}}
			}),
			builder.WithPredicates(nsPredicate),
		).
		Complete(r)
}
