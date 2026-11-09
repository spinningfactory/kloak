package controller

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// Uninstall signalling (spinningfactory/kloak#107). The eBPF programs
// outlive a controller that restarts, so deleting kloak must tell every
// controller to tear its node's data plane down: the Helm chart's
// pre-delete hook (`kloak uninstall-hook`) annotates the controllers'
// DaemonSet with UninstallAnnotation, and waits for each controller pod to
// report UninstalledCondition.
const (
	// UninstallAnnotation on the controller DaemonSet (its value is the
	// time the uninstall started) asks every controller to tear down its
	// node's data plane.
	UninstallAnnotation = "getkloak.io/uninstall"
	// UninstalledCondition is the condition a controller pod reports, True,
	// once it has torn down its node's data plane.
	UninstalledCondition corev1.PodConditionType = "getkloak.io/Uninstalled"
	// PinFormatAnnotation on the controller DaemonSet's pod template says
	// that the controllers it runs adopt (or tear down) the eBPF objects a
	// previous one left pinned: the layout they read (ebpf pinFormat, "1"). A
	// stopping controller keeps them only for such a successor: one of a
	// version before them, or with persistence off, would attach its own
	// next to them, and each record would be patched twice.
	PinFormatAnnotation = "getkloak.io/pin-format"
)

// UninstallWatcher watches the controller's own DaemonSet, and tears down the
// node's data plane once it carries UninstallAnnotation.
type UninstallWatcher struct {
	client.Client
	// Namespace and Name are the DaemonSet's.
	Namespace, Name string
	// PodName is this controller's pod, in Namespace (POD_NAME): its
	// UninstalledCondition reports the teardown. "" reports nothing.
	PodName string
	// Uninstall tears down the node's data plane
	// (TLSUprobeManager.Uninstall). It runs once.
	Uninstall func() error
	Log       *zap.SugaredLogger

	done     atomic.Bool
	reported atomic.Bool
}

// Uninstalled reports whether the data plane was torn down: the controller
// is then no longer ready.
func (w *UninstallWatcher) Uninstalled() bool { return w.done.Load() }

// ReadyCheck fails once the data plane was torn down, for the readiness
// probe (healthz.Checker).
func (w *UninstallWatcher) ReadyCheck(_ *http.Request) error {
	if w.Uninstalled() {
		return errors.New("uninstalled: the eBPF data plane of this node was torn down")
	}
	return nil
}

// Reconcile tears the data plane down when the DaemonSet asks for it, and
// reports it on the controller's pod.
func (w *UninstallWatcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ds := &appsv1.DaemonSet{}
	if err := w.Get(ctx, req.NamespacedName, ds); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	started, ok := ds.Annotations[UninstallAnnotation]
	if !ok {
		return ctrl.Result{}, nil
	}
	if w.done.CompareAndSwap(false, true) {
		w.Log.Infow("kloak is being uninstalled: tearing down this node's eBPF data plane", "daemonset", req.NamespacedName, "since", started)
		if err := w.Uninstall(); err != nil {
			// The teardown runs once: what failed is logged, and is left
			// to a reboot or `kloak cleanup`.
			w.Log.Errorw("tearing down the eBPF data plane for the uninstall failed in part", "error", err)
		}
	}
	if w.PodName == "" || w.reported.Load() {
		return ctrl.Result{}, nil
	}
	if err := w.reportUninstalled(ctx); err != nil {
		w.Log.Warnw("reporting the teardown on the controller's pod failed; retrying", "pod", w.PodName, "error", err)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	w.reported.Store(true)
	return ctrl.Result{}, nil
}

// reportUninstalled sets UninstalledCondition on the controller's pod. A
// strategic merge patch merges conditions by type: kubelet's are kept, and
// kubelet keeps this one (it updates only the conditions it owns).
func (w *UninstallWatcher) reportUninstalled(ctx context.Context) error {
	pod := &corev1.Pod{}
	if err := w.Get(ctx, types.NamespacedName{Namespace: w.Namespace, Name: w.PodName}, pod); err != nil {
		return err
	}
	patch := client.StrategicMergeFrom(pod.DeepCopy())
	cond := corev1.PodCondition{
		Type:               UninstalledCondition,
		Status:             corev1.ConditionTrue,
		Reason:             "Uninstalled",
		Message:            "the eBPF data plane of this node was torn down for the uninstall",
		LastTransitionTime: metav1.Now(),
	}
	replaced := false
	for i := range pod.Status.Conditions {
		if pod.Status.Conditions[i].Type == UninstalledCondition {
			pod.Status.Conditions[i] = cond
			replaced = true
		}
	}
	if !replaced {
		pod.Status.Conditions = append(pod.Status.Conditions, cond)
	}
	return w.Status().Patch(ctx, pod, patch)
}

// SetupWithManager watches the DaemonSet Namespace/Name only.
func (w *UninstallWatcher) SetupWithManager(mgr ctrl.Manager) error {
	own := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetNamespace() == w.Namespace && o.GetName() == w.Name
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("uninstall").
		For(&appsv1.DaemonSet{}, builder.WithPredicates(own)).
		Complete(w)
}
