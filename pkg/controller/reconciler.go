// Package controller provides the Kubernetes controller for watching pods
// and managing eBPF program attachments.
package controller

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spinningfactory/kloak/pkg/cgroups"
	"github.com/spinningfactory/kloak/pkg/ebpf"
)

const (
	// AnnotationEnabled is the annotation that enables Kloak for a pod.
	AnnotationEnabled = "getkloak.io/enabled"

	// CgroupBasePath is the base path for cgroups v2.
	CgroupBasePath = "/sys/fs/cgroup"
)

// Reconciler watches pods and manages eBPF cgroup tracking.
type Reconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	UprobeManager *ebpf.TLSUprobeManager
	CgroupRoot    string
	// NodeName filters pods to only those on this node (empty = all nodes)
	NodeName string

	mu sync.RWMutex
	// trackedPods maps pod UID -> set of cgroup IDs (one per container).
	// Value is true if uprobes were successfully attached, false if attachment
	// failed (e.g. libssl not loaded yet) and should be retried.
	trackedPods map[string]map[uint64]bool

	// podKeyToUID maps "namespace/name" -> pod UID, so that on a NotFound
	// delete event (where we only have the namespaced name) we can look up
	// the UID and clean up trackedPods correctly.
	podKeyToUID map[string]string

	// podTGIDs maps pod UID -> slice of TGIDs registered in the tracked_tgids
	// BPF map. Used to call UntrackTGID on pod deletion so the DNS/connect
	// tracepoints stop processing syscalls for dead process groups.
	podTGIDs map[string][]uint32
}

// NewReconciler creates a new pod reconciler.
func NewReconciler(c client.Client, log logr.Logger, scheme *runtime.Scheme, uprobeMgr *ebpf.TLSUprobeManager, cgroupRoot, nodeName string) *Reconciler {
	if cgroupRoot == "" {
		cgroupRoot = CgroupBasePath
	}
	return &Reconciler{
		Client:        c,
		Log:           log,
		Scheme:        scheme,
		UprobeManager: uprobeMgr,
		CgroupRoot:    cgroupRoot,
		NodeName:      nodeName,
		trackedPods:   make(map[string]map[uint64]bool),
		podKeyToUID:   make(map[string]string),
		podTGIDs:      make(map[string][]uint32),
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
		// Pod was deleted — look up the UID we stored on the last successful
		// reconcile so we can find the entry in trackedPods (keyed by UID).
		r.mu.RLock()
		uid, known := r.podKeyToUID[req.String()]
		r.mu.RUnlock()
		if !known {
			return ctrl.Result{}, nil
		}
		return r.handleDelete(uid, req.String())
	}

	// Check if Kloak is enabled
	if !r.isEnabled(pod) {
		// If was tracked before, clean up
		r.mu.RLock()
		_, tracked := r.trackedPods[string(pod.UID)]
		r.mu.RUnlock()
		if tracked {
			return r.handleDelete(string(pod.UID), req.String())
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
		return ctrl.Result{Requeue: true}, nil
	}

	// Compute cgroup diff under the lock, then attach uprobes outside it.
	// attachUprobesToCgroup does blocking filesystem I/O and must not run
	// while the lock is held to avoid blocking other reconcile goroutines.
	var needsAttach []uint64

	r.mu.Lock()
	existingCgroups := r.trackedPods[string(pod.UID)]
	if existingCgroups == nil {
		existingCgroups = make(map[uint64]bool)
	}

	// Collect cgroups that need uprobe attachment:
	// - New cgroups not yet tracked
	// - Previously tracked cgroups where attachment failed (value=false)
	for cgroupID := range cgroupIDs {
		attached, tracked := existingCgroups[cgroupID]
		if !tracked {
			existingCgroups[cgroupID] = false // tracked but not yet attached
			log.Info("tracking container cgroup", "cgroupID", cgroupID)
			needsAttach = append(needsAttach, cgroupID)
		} else if !attached {
			// Retry attachment (e.g. libssl not loaded on first attempt)
			needsAttach = append(needsAttach, cgroupID)
		}
	}

	// Remove old cgroups that are no longer present (container restarted with new cgroup)
	for cgroupID := range existingCgroups {
		if !cgroupIDs[cgroupID] {
			delete(existingCgroups, cgroupID)
			log.Info("removed stale cgroup", "cgroupID", cgroupID)
		}
	}

	r.trackedPods[string(pod.UID)] = existingCgroups
	r.podKeyToUID[req.String()] = string(pod.UID)
	r.mu.Unlock()

	// Attach uprobes outside the lock — this involves filesystem I/O.
	for _, cgroupID := range needsAttach {
		if tgids := r.attachUprobesToCgroup(cgroupID, pod); len(tgids) > 0 {
			r.mu.Lock()
			if tracked := r.trackedPods[string(pod.UID)]; tracked != nil {
				tracked[cgroupID] = true // mark as successfully attached
			}
			r.podTGIDs[string(pod.UID)] = append(r.podTGIDs[string(pod.UID)], tgids...)
			r.mu.Unlock()
		}
	}

	// If any cgroups still need attachment, requeue to retry later.
	// This handles runtimes like Python where libssl loads lazily.
	r.mu.RLock()
	needsRetry := false
	if tracked := r.trackedPods[string(pod.UID)]; tracked != nil {
		for _, attached := range tracked {
			if !attached {
				needsRetry = true
				break
			}
		}
	}
	r.mu.RUnlock()

	if needsRetry {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

// attachUprobesToCgroup reads the cgroup's procs file to find a PID and calls the uprobe manager.
// Returns the TGIDs (process group IDs) for which uprobes were successfully attached, or nil if none.
func (r *Reconciler) attachUprobesToCgroup(cgroupID uint64, pod *corev1.Pod) []uint32 {
	if r.UprobeManager == nil {
		return nil
	}

	r.Log.Info("Trying to attach uprobes to new container", "cgroup", cgroupID)

	// Find the container cgroup path again to read cgroup.procs
	for i := range pod.Status.ContainerStatuses {
		status := &pod.Status.ContainerStatuses[i]
		if status.ContainerID == "" {
			continue
		}
		parts := strings.SplitN(status.ContainerID, "://", 2)
		if len(parts) != 2 {
			continue
		}
		containerID := parts[1]

		containerCgroupPath, err := cgroups.FindContainerCgroupPath(r.CgroupRoot, string(pod.UID), containerID)
		if err != nil {
			continue
		}

		// Verify this is the right cgroup by checking inode
		inode, err := cgroups.GetCgroupInodeFromPath(containerCgroupPath)
		if err != nil || inode != cgroupID {
			continue
		}

		// Read PIDs from cgroup.procs
		pids, err := cgroups.ReadCgroupProcs(containerCgroupPath)
		if err != nil {
			r.Log.Error(err, "failed to read cgroup.procs", "path", containerCgroupPath)
			return nil
		}

		if len(pids) == 0 {
			r.Log.V(1).Info("no PIDs found in cgroup.procs", "path", containerCgroupPath)
			return nil
		}

		// Attempt to attach uprobes to every PID in the cgroup.
		// Containers may run multiple processes; we probe all of them so that
		// whichever process makes TLS calls is instrumented. AttachTLS skips
		// PIDs that have no compatible TLS symbols.
		// cgroup.procs lists TGIDs (process group leaders), so pid == tgid here.
		var attachedTGIDs []uint32
		for _, pid := range pids {
			if err := r.UprobeManager.AttachTLS(pid); err != nil {
				r.Log.V(1).Info("could not attach TLS uprobes to pid (no compatible symbols or already attached)", "pid", pid, "container", status.Name, "err", err)
			} else {
				r.Log.Info("Successfully attached TLS uprobes", "pid", pid, "container", status.Name)
				attachedTGIDs = append(attachedTGIDs, uint32(pid))
			}
		}
		return attachedTGIDs
	}

	r.Log.V(1).Info("could not find matching container for cgroup", "cgroupID", cgroupID)
	return nil
}

// handleDelete removes a pod from tracking. uid is the pod UID (trackedPods key),
// namespacedName is the "namespace/name" string (podKeyToUID key).
func (r *Reconciler) handleDelete(uid, namespacedName string) (ctrl.Result, error) {
	r.mu.Lock()
	cgroupIDs, tracked := r.trackedPods[uid]
	if !tracked {
		r.mu.Unlock()
		return ctrl.Result{}, nil
	}

	tgids := r.podTGIDs[uid]
	// Uprobes will be automatically cleaned up by the uprobe component when
	// the process dies, so we no longer have to detach them manually or remove cgroups from maps.
	// Just remove the pod from our tracking.
	delete(r.trackedPods, uid)
	delete(r.podKeyToUID, namespacedName)
	delete(r.podTGIDs, uid)
	r.mu.Unlock()
	r.Log.Info("stopped tracking pod", "pod", namespacedName, "uid", uid, "cgroupCount", len(cgroupIDs))

	// Remove TGIDs from the tracked_tgids BPF map so DNS/connect tracepoints
	// stop processing syscalls for these dead process groups.
	if r.UprobeManager != nil {
		for _, tgid := range tgids {
			r.UprobeManager.UntrackTGID(tgid)
		}
	}

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
		for i := range statuses {
			status := &statuses[i]
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.trackedPods)
}
