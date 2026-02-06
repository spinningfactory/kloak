// Package controller provides the Kubernetes controller for watching pods
// and managing eBPF program attachments.
package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"
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

	// trackedPods maps pod UID -> cgroup ID
	trackedPods map[string]uint64
}

// NewReconciler creates a new pod reconciler.
func NewReconciler(c client.Client, log logr.Logger, scheme *runtime.Scheme, cgroupMgr CgroupManager, cgroupRoot string) *Reconciler {
	if cgroupRoot == "" {
		cgroupRoot = CgroupBasePath
	}
	return &Reconciler{
		Client:        c,
		Log:           log,
		Scheme:        scheme,
		CgroupManager: cgroupMgr,
		CgroupRoot:    cgroupRoot,
		trackedPods:   make(map[string]uint64),
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

	// Pod is running and enabled
	if pod.Status.Phase != corev1.PodRunning {
		log.V(1).Info("pod not running yet", "phase", pod.Status.Phase)
		return ctrl.Result{}, nil
	}

	// Get the cgroup ID for this pod
	cgroupID, err := r.getCgroupID(pod)
	if err != nil {
		// This is expected during container startup - will retry on next reconcile
		log.V(1).Info("cgroup ID not available yet", "reason", err.Error())
		return ctrl.Result{Requeue: true}, nil // Retry after a bit
	}

	// Track the pod
	if existingCgroup, tracked := r.trackedPods[string(pod.UID)]; tracked {
		if existingCgroup == cgroupID {
			return ctrl.Result{}, nil // Already tracked
		}
		// Cgroup changed (shouldn't happen normally)
		_ = r.CgroupManager.RemoveCgroup(existingCgroup)
	}

	// Add to eBPF map
	if err := r.CgroupManager.AddCgroup(cgroupID); err != nil {
		log.Error(err, "failed to add cgroup to eBPF map", "cgroupID", cgroupID)
		return ctrl.Result{}, err
	}

	r.trackedPods[string(pod.UID)] = cgroupID
	log.Info("tracking pod", "cgroupID", cgroupID)

	return ctrl.Result{}, nil
}

// handleDelete removes a pod from tracking.
func (r *Reconciler) handleDelete(podKey string) (ctrl.Result, error) {
	cgroupID, tracked := r.trackedPods[podKey]
	if !tracked {
		return ctrl.Result{}, nil
	}

	if err := r.CgroupManager.RemoveCgroup(cgroupID); err != nil {
		r.Log.Error(err, "failed to remove cgroup from eBPF map", "cgroupID", cgroupID)
	}

	delete(r.trackedPods, podKey)
	r.Log.Info("stopped tracking pod", "podKey", podKey, "cgroupID", cgroupID)

	return ctrl.Result{}, nil
}

// isEnabled checks if Kloak should process this pod.
func (r *Reconciler) isEnabled(pod *corev1.Pod) bool {
	if pod.Annotations == nil {
		return false
	}
	return pod.Annotations[AnnotationEnabled] == "true"
}

// getCgroupID retrieves the cgroup ID for a pod's containers.
// For cgroups v2, we get the inode number of the cgroup directory.
func (r *Reconciler) getCgroupID(pod *corev1.Pod) (uint64, error) {
	// Try to find a running container
	for _, status := range pod.Status.ContainerStatuses {
		if status.ContainerID == "" {
			continue
		}

		// Extract container ID (format: containerd://abc123...)
		parts := strings.SplitN(status.ContainerID, "://", 2)
		if len(parts) != 2 {
			continue
		}
		containerID := parts[1]

		// Find the cgroup path for this container
		cgroupPath, err := r.findCgroupPath(pod, containerID)
		if err != nil {
			continue
		}

		// Get the inode number (cgroup ID)
		return r.getCgroupInode(cgroupPath)
	}

	return 0, fmt.Errorf("no running container found for pod %s/%s", pod.Namespace, pod.Name)
}

// findCgroupPath finds the cgroup path for a container.
func (r *Reconciler) findCgroupPath(pod *corev1.Pod, containerID string) (string, error) {
	// Common patterns for Kubernetes cgroups v2:
	// - kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<containerID>.scope
	// - kubepods/burstable/pod<uid>/<containerID>

	podUID := string(pod.UID)
	podUIDUnderscored := strings.ReplaceAll(podUID, "-", "_")

	patterns := []string{
		// containerd pattern
		filepath.Join(r.CgroupRoot, "kubepods.slice", "kubepods-burstable.slice",
			fmt.Sprintf("kubepods-burstable-pod%s.slice", podUIDUnderscored),
			fmt.Sprintf("cri-containerd-%s.scope", containerID)),
		// containerd pattern (BestEffort)
		filepath.Join(r.CgroupRoot, "kubepods.slice", "kubepods-besteffort.slice",
			fmt.Sprintf("kubepods-besteffort-pod%s.slice", podUIDUnderscored),
			fmt.Sprintf("cri-containerd-%s.scope", containerID)),
		// Alternative pattern
		filepath.Join(r.CgroupRoot, "kubepods", "burstable",
			fmt.Sprintf("pod%s", podUID), containerID),
		// Best-effort pattern
		filepath.Join(r.CgroupRoot, "kubepods", "pod"+podUID),
	}

	for _, path := range patterns {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("cgroup path not found for container %s", containerID)
}

// getCgroupInode gets the inode number of a cgroup directory.
func (r *Reconciler) getCgroupInode(cgroupPath string) (uint64, error) {
	stat, err := os.Stat(cgroupPath)
	if err != nil {
		return 0, err
	}

	// Get the inode from the FileInfo
	// This works on Linux but we need the syscall for the actual inode
	return getCgroupInodeFromPath(cgroupPath, stat)
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
