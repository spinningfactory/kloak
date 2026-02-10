// Package controller provides the Kubernetes controller for watching pods
// and managing eBPF program attachments.
package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/spinningfactory/kloak/pkg/cgroups"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// AnnotationEnabled is the annotation that enables Kloak for a pod.
	AnnotationEnabled = "getkloak.io/enabled"

	// CgroupBasePath is the base path for cgroups v2.
	CgroupBasePath = "/sys/fs/cgroup"
)

// CgroupManager is the interface for managing cgroups in eBPF maps.
type CgroupManager interface {
	AddCgroup(cgroupID uint64) error
	RemoveCgroup(cgroupID uint64) error
}

// Reconciler watches pods and manages eBPF cgroup tracking.
type Reconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	CgroupManager CgroupManager
	CgroupRoot    string
	// NodeName filters pods to only those on this node (empty = all nodes)
	NodeName string

	// trackedPods maps pod UID -> set of cgroup IDs (one per container)
	trackedPods map[string]map[uint64]bool
}

// NewReconciler creates a new pod reconciler.
// nodeName filters pods to only those on this node (empty = all nodes).
func NewReconciler(c client.Client, log logr.Logger, scheme *runtime.Scheme, cgroupMgr CgroupManager, cgroupRoot, nodeName string) *Reconciler {
	if cgroupRoot == "" {
		cgroupRoot = CgroupBasePath
	}
	return &Reconciler{
		Client:        c,
		Log:           log,
		Scheme:        scheme,
		CgroupManager: cgroupMgr,
		CgroupRoot:    cgroupRoot,
		NodeName:      nodeName,
		trackedPods:   make(map[string]map[uint64]bool),
	}
}

// Reconcile handles pod create/update/delete events.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("pod", req.NamespacedName)

	// Fetch the pod
	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// Pod was deleted - clean up
		return r.handleDelete(req.NamespacedName.String())
	}

	// Check if Kloak is enabled
	if !r.isEnabled(pod) {
		// If was tracked before, clean up
		if _, tracked := r.trackedPods[string(pod.UID)]; tracked {
			return r.handleDelete(string(pod.UID))
		}
		return ctrl.Result{}, nil
	}

	// Filter by node if NodeName is set (per-node controller)
	if r.NodeName != "" && pod.Spec.NodeName != r.NodeName {
		log.V(1).Info("skipping pod on different node", "podNode", pod.Spec.NodeName, "ourNode", r.NodeName)
		return ctrl.Result{}, nil
	}

	// Pod is running and enabled
	if pod.Status.Phase != corev1.PodRunning {
		log.V(1).Info("pod not running yet", "phase", pod.Status.Phase)
		return ctrl.Result{}, nil
	}

	// Get cgroup IDs for all containers in this pod
	cgroupIDs, err := r.getContainerCgroupIDs(pod)
	if err != nil {
		// This is expected during container startup - will retry on next reconcile
		log.V(1).Info("cgroup IDs not available yet", "reason", err.Error())
		return ctrl.Result{Requeue: true}, nil // Retry after a bit
	}

	// Get existing tracked cgroups for this pod
	existingCgroups := r.trackedPods[string(pod.UID)]
	if existingCgroups == nil {
		existingCgroups = make(map[uint64]bool)
	}

	// Add new cgroups that aren't already tracked
	for cgroupID := range cgroupIDs {
		if !existingCgroups[cgroupID] {
			if err := r.CgroupManager.AddCgroup(cgroupID); err != nil {
				log.Error(err, "failed to add cgroup to eBPF map", "cgroupID", cgroupID)
				continue
			}
			existingCgroups[cgroupID] = true
			log.Info("tracking container cgroup", "cgroupID", cgroupID)
		}
	}

	// Remove old cgroups that are no longer present (container restarted with new cgroup)
	for cgroupID := range existingCgroups {
		if !cgroupIDs[cgroupID] {
			_ = r.CgroupManager.RemoveCgroup(cgroupID)
			delete(existingCgroups, cgroupID)
			log.Info("removed stale cgroup", "cgroupID", cgroupID)
		}
	}

	r.trackedPods[string(pod.UID)] = existingCgroups

	return ctrl.Result{}, nil
}

// handleDelete removes a pod from tracking.
func (r *Reconciler) handleDelete(podKey string) (ctrl.Result, error) {
	cgroupIDs, tracked := r.trackedPods[podKey]
	if !tracked {
		return ctrl.Result{}, nil
	}

	for cgroupID := range cgroupIDs {
		if err := r.CgroupManager.RemoveCgroup(cgroupID); err != nil {
			r.Log.Error(err, "failed to remove cgroup from eBPF map", "cgroupID", cgroupID)
		}
	}

	delete(r.trackedPods, podKey)
	r.Log.Info("stopped tracking pod", "podKey", podKey, "cgroupCount", len(cgroupIDs))

	return ctrl.Result{}, nil
}

// isEnabled checks if Kloak should process this pod.
func (r *Reconciler) isEnabled(pod *corev1.Pod) bool {
	if pod.Annotations == nil {
		return false
	}
	return pod.Annotations[AnnotationEnabled] == "true"
}

// getContainerCgroupIDs retrieves the cgroup IDs for all running containers in a pod.
// For cgroups v2, we get the inode number of each container's cgroup directory.
// We track container cgroups (not pod cgroups) because bpf_get_current_cgroup_id()
// returns the container's .scope cgroup, not the pod's .slice cgroup.
func (r *Reconciler) getContainerCgroupIDs(pod *corev1.Pod) (map[uint64]bool, error) {
	cgroupIDs := make(map[uint64]bool)

	// Helper to collect cgroup IDs from container statuses
	collectFromStatuses := func(statuses []corev1.ContainerStatus) {
		for _, status := range statuses {
			if status.ContainerID == "" {
				continue
			}

			// Extract container ID (format: containerd://abc123...)
			parts := strings.SplitN(status.ContainerID, "://", 2)
			if len(parts) != 2 {
				continue
			}
			containerID := parts[1]

			// Get the container's cgroup path (not the pod's parent cgroup)
			containerCgroupPath, err := cgroups.FindContainerCgroupPath(r.CgroupRoot, string(pod.UID), containerID)
			if err != nil {
				r.Log.V(1).Info("could not find container cgroup", "container", status.Name, "err", err)
				continue
			}

			cgroupID, err := cgroups.GetCgroupInodeFromPath(containerCgroupPath)
			if err != nil {
				r.Log.V(1).Info("could not get cgroup inode", "container", status.Name, "path", containerCgroupPath, "err", err)
				continue
			}

			r.Log.Info("Found container cgroup", "container", status.Name, "cgroupPath", containerCgroupPath, "cgroupID", cgroupID)
			cgroupIDs[cgroupID] = true
		}
	}

	// Collect from app containers (these are the ones that matter for traffic interception)
	collectFromStatuses(pod.Status.ContainerStatuses)

	// Also collect from init containers if they're still running
	collectFromStatuses(pod.Status.InitContainerStatuses)

	if len(cgroupIDs) == 0 {
		return nil, fmt.Errorf("no container cgroups found for pod %s/%s", pod.Namespace, pod.Name)
	}

	return cgroupIDs, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}

// GetTrackedPodCount returns the number of currently tracked pods.
func (r *Reconciler) GetTrackedPodCount() int {
	return len(r.trackedPods)
}
