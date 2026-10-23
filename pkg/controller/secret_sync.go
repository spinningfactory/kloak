package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	k8ssecrets "github.com/spinningfactory/kloak/pkg/secrets/k8s"
)

// DefaultSecretResyncPeriod is how often the data plane's secrets are synced
// when no Secret changes: what releases the virtual IP of a host no secret
// is restricted to any more once its retention is over, and repairs maps
// that drifted.
const DefaultSecretResyncPeriod = 5 * time.Minute

// secretSyncRequest is the only request SecretSyncReconciler handles: every
// sync is a full one, so the workqueue folds a burst of Secret events (an
// enabled Secret, then its shadow) into one or two syncs.
var secretSyncRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "kloak-secrets"}}

// SecretSyncReconciler keeps the data plane's secrets in step with the
// cluster's kloak Secrets: an enabled Secret or a shadow that is created,
// changed or deleted triggers a sync.
type SecretSyncReconciler struct {
	// Sync makes the data plane hold the cluster's current secrets
	// (TLSUprobeManager.SyncSecrets). An error is logged by the controller
	// and retried with backoff.
	Sync func(context.Context) error
	// ResyncPeriod is the time between syncs when nothing changes;
	// 0 means DefaultSecretResyncPeriod.
	ResyncPeriod time.Duration
}

// Reconcile syncs every secret. Every request is secretSyncRequest.
func (r *SecretSyncReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	if err := r.Sync(ctx); err != nil {
		return ctrl.Result{}, err
	}
	period := r.ResyncPeriod
	if period == 0 {
		period = DefaultSecretResyncPeriod
	}
	return ctrl.Result{RequeueAfter: period}, nil
}

// isKloakSecret reports whether a Secret is one the data plane reads (see
// k8ssecrets.Source): enabled, or a shadow.
func isKloakSecret(o client.Object) bool {
	l := o.GetLabels()
	return l[k8ssecrets.LabelEnabled] == "true" || l[k8ssecrets.LabelManaged] == "true"
}

// secretSyncHandler enqueues secretSyncRequest for the events of kloak
// Secrets. The filter is a map function, not a predicate: on an update it
// runs on both the old and the new object, so a Secret whose label was just
// removed still triggers the sync that drops it. A predicate built with
// predicate.NewPredicateFuncs only sees the new object.
func secretSyncHandler() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		if !isKloakSecret(o) {
			return nil
		}
		return []reconcile.Request{secretSyncRequest}
	})
}

// SetupWithManager watches Secrets, through the cache the Secret reconciler
// already fills, and syncs once at start: with no kloak Secret there is no
// event, and the virtual IPs restored from the pinned maps still need to
// be retired.
func (r *SecretSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("secret-sync").
		Watches(&corev1.Secret{}, secretSyncHandler()).
		WatchesRawSource(source.Func(func(_ context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
			q.Add(secretSyncRequest)
			return nil
		})).
		Complete(r)
}
