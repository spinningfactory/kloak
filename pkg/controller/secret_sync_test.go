package controller

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestSecretSyncReconciler(t *testing.T) {
	syncs := 0
	var fail error
	r := &SecretSyncReconciler{Sync: func(context.Context) error {
		syncs++
		return fail
	}}

	res, err := r.Reconcile(context.Background(), secretSyncRequest)
	if err != nil || res.RequeueAfter != DefaultSecretResyncPeriod || syncs != 1 {
		t.Fatalf("Reconcile = %+v, %v after %d syncs, want a resync in %v after 1", res, err, syncs, DefaultSecretResyncPeriod)
	}

	r.ResyncPeriod = 30 * DefaultSecretResyncPeriod
	if res, err := r.Reconcile(context.Background(), secretSyncRequest); err != nil || res.RequeueAfter != r.ResyncPeriod {
		t.Fatalf("Reconcile with a resync period = %+v, %v", res, err)
	}

	// A failed sync is returned, for the request to be retried with backoff.
	fail = errors.New("secret_map: 1 failed map operations")
	if _, err := r.Reconcile(context.Background(), secretSyncRequest); !errors.Is(err, fail) {
		t.Fatalf("Reconcile with a failing sync = %v, want its error", err)
	}
}

func TestSecretSyncHandler(t *testing.T) {
	secret := func(labels map[string]string, annotations map[string]string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "s", Labels: labels, Annotations: annotations,
		}}
	}
	enabled := secret(map[string]string{"getkloak.io/enabled": "true"}, nil)
	shadow := secret(map[string]string{"getkloak.io/managed": "true", "getkloak.io/owner": "s"}, nil)
	plain := secret(map[string]string{"app": "web"}, nil)
	// The data plane only reads enabled Secrets by label.
	annotated := secret(nil, map[string]string{"getkloak.io/enabled": "true"})

	h := secretSyncHandler()
	ctx := context.Background()
	tests := []struct {
		name string
		send func(workqueue.TypedRateLimitingInterface[reconcile.Request])
		want bool
	}{
		{"enabled created", func(q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			h.Create(ctx, event.CreateEvent{Object: enabled}, q)
		}, true},
		{"shadow created", func(q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			h.Create(ctx, event.CreateEvent{Object: shadow}, q)
		}, true},
		{"plain secret created", func(q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			h.Create(ctx, event.CreateEvent{Object: plain}, q)
		}, false},
		{"enabled by annotation only", func(q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			h.Create(ctx, event.CreateEvent{Object: annotated}, q)
		}, false},
		{"enabled label removed", func(q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			h.Update(ctx, event.UpdateEvent{ObjectOld: enabled, ObjectNew: plain}, q)
		}, true},
		{"plain secret updated", func(q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			h.Update(ctx, event.UpdateEvent{ObjectOld: plain, ObjectNew: plain}, q)
		}, false},
		{"shadow deleted", func(q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			h.Delete(ctx, event.DeleteEvent{Object: shadow}, q)
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
			defer q.ShutDown()
			tc.send(q)
			if !tc.want {
				if q.Len() != 0 {
					t.Fatalf("%d requests queued, want none", q.Len())
				}
				return
			}
			// Both objects of an update map to the one request.
			if q.Len() != 1 {
				t.Fatalf("%d requests queued, want 1", q.Len())
			}
			if req, _ := q.Get(); req != secretSyncRequest {
				t.Fatalf("queued %v, want %v", req, secretSyncRequest)
			}
		})
	}
}

// TestSecretSyncSetup checks that the builder accepts the secret sync's
// watches (a named controller with no For). Nothing is started, so no API
// server is needed.
func TestSecretSyncSetup(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	mgr, err := ctrl.NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		// Controller names are checked process-wide: go test -count=2
		// would register "secret-sync" twice.
		Controller: config.Controller{SkipNameValidation: ptr(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &SecretSyncReconciler{Sync: func(context.Context) error { return nil }}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}
}
