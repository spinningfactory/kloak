// Package controller provides the Kubernetes controller for watching pods
// and managing eBPF program attachments.
package controller

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spinningfactory/kloak/pkg/cgroups"
	"github.com/spinningfactory/kloak/pkg/ebpf"
	"github.com/spinningfactory/kloak/pkg/logging"
	k8ssecrets "github.com/spinningfactory/kloak/pkg/secrets/k8s"
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
	Log           *zap.SugaredLogger
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
}

// NewReconciler creates a new pod reconciler.
func NewReconciler(c client.Client, log *zap.SugaredLogger, scheme *runtime.Scheme, uprobeMgr *ebpf.TLSUprobeManager, cgroupRoot, nodeName string) *Reconciler {
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
	}
}

// Reconcile handles pod create/update/delete events.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With("pod", req.NamespacedName)

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
		log.Debugw("skipping pod on different node", "podNode", pod.Spec.NodeName, "ourNode", r.NodeName)
		return ctrl.Result{}, nil
	}

	addrs := podIPs(pod)

	// Pod is running and enabled
	if pod.Status.Phase != corev1.PodRunning {
		// Virtual-ip mode: bind the pod and attach the DNS rewrite as soon
		// as it has its network (its sandbox runs), so that its containers,
		// init containers first, mostly start with the rewrite in place. A
		// lookup made before gets the real addresses.
		if pod.Status.Phase != corev1.PodPending || len(addrs) == 0 || !r.virtualIP() {
			log.Debugw("pod not running yet", "phase", pod.Status.Phase)
			return ctrl.Result{}, nil
		}
		r.mu.Lock()
		if r.trackedPods[string(pod.UID)] == nil {
			r.trackedPods[string(pod.UID)] = make(map[uint64]bool)
		}
		r.podKeyToUID[req.String()] = string(pod.UID)
		r.mu.Unlock()
		r.UprobeManager.BindPodSecrets(string(pod.UID), req.String(), addrs, nil, k8ssecrets.PodSecretRefs(pod))
		if !r.attachDNSRewrite(pod, req.String()) {
			return ctrl.Result{RequeueAfter: 500 * time.Millisecond}, nil
		}
		return ctrl.Result{}, nil
	}

	// Get cgroup IDs for all containers in this pod
	cgroupIDs, err := r.getContainerCgroupIDs(pod)
	if err != nil {
		// This is expected during container startup - will retry on next reconcile
		log.Debugw("cgroup IDs not available yet", "reason", err.Error())
		return ctrl.Result{Requeue: true}, nil //nolint:staticcheck // SA1019: keep the rate-limited backoff; RequeueAfter is a fixed delay
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
			log.Infow("tracking container cgroup", "cgroupID", cgroupID)
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
			log.Infow("removed stale cgroup", "cgroupID", cgroupID)
		}
	}

	r.trackedPods[string(pod.UID)] = existingCgroups
	r.podKeyToUID[req.String()] = string(pod.UID)
	r.mu.Unlock()

	// Bind before attaching, so that by the time the uprobes fire this pod's
	// containers can redeem exactly the secrets its spec references. Rebinding
	// on every reconcile picks up containers restarted with a new cgroup.
	if r.UprobeManager != nil {
		ids := make([]uint64, 0, len(cgroupIDs))
		for id := range cgroupIDs {
			ids = append(ids, id)
		}
		r.UprobeManager.BindPodSecrets(string(pod.UID), req.String(), addrs, ids, k8ssecrets.PodSecretRefs(pod))
	}
	// Also for pods running before the controller started, and for a pod
	// whose sandbox was recreated (a new netns).
	dnsAttached := r.attachDNSRewrite(pod, req.String())

	// Attach uprobes outside the lock — this involves filesystem I/O.
	for _, cgroupID := range needsAttach {
		cgroupPath, pid := r.attachUprobesToCgroup(cgroupID, pod)
		if cgroupPath != "" {
			r.mu.Lock()
			if tracked := r.trackedPods[string(pod.UID)]; tracked != nil {
				tracked[cgroupID] = true // mark as successfully attached
			}
			r.mu.Unlock()

			// Register the cgroup for exec/exit tracepoint tracking so new
			// processes spawned inside the container are automatically detected.
			if r.UprobeManager != nil {
				if err := r.UprobeManager.TrackCgroup(cgroupID, cgroupPath); err != nil {
					log.Errorw("failed to track cgroup for exec events", "error", err, "cgroupID", cgroupID)
				}
				// Record which netns this cgroup belongs to, so UntrackCgroup
				// can clean up the pinned netns fd and allow inode reuse.
				if pid > 0 {
					r.UprobeManager.RecordCgroupNetns(cgroupID, pid)
				}
			}
		}
	}

	// If any cgroups still need attachment, requeue to retry later.
	// This handles runtimes like Python where libssl loads lazily.
	r.mu.RLock()
	needsRetry := !dnsAttached
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
		return ctrl.Result{RequeueAfter: 500 * time.Millisecond}, nil
	}
	return ctrl.Result{}, nil
}

// attachUprobesToCgroup reads the cgroup's procs file to find a PID and calls the uprobe manager.
// Returns the cgroup filesystem path and one of the container's PIDs on success, or empty string and 0 on failure.
func (r *Reconciler) attachUprobesToCgroup(cgroupID uint64, pod *corev1.Pod) (cgroupPath string, attachedPID int) {
	if r.UprobeManager == nil {
		return "", 0
	}

	logging.Tracew(r.Log, "trying to attach uprobes to container", "cgroup", cgroupID)

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
			r.Log.Errorw("failed to read cgroup.procs", "error", err, "path", containerCgroupPath)
			return "", 0
		}

		if len(pids) == 0 {
			r.Log.Debugw("no PIDs found in cgroup.procs", "path", containerCgroupPath)
			return "", 0
		}

		// Attempt to attach uprobes to every PID in the cgroup.
		// Containers may run multiple processes; we probe all of them so that
		// whichever process makes TLS calls is instrumented. AttachTLS skips
		// PIDs that have no compatible TLS symbols.
		attached := false
		attachedPid := 0
		for _, pid := range pids {
			if err := r.UprobeManager.AttachTLS(pid, cgroupID); err != nil {
				logging.Tracew(r.Log, "could not attach TLS uprobes to pid", "pid", pid, "container", status.Name, "err", err)
			} else {
				r.Log.Infow("Successfully attached TLS uprobes", "pid", pid, "container", status.Name)
				attached = true
				if attachedPid == 0 {
					attachedPid = pid
				}
			}
		}
		if attached {
			return containerCgroupPath, attachedPid
		}
		return "", 0
	}

	r.Log.Debugw("could not find matching container for cgroup", "cgroupID", cgroupID)
	return "", 0
}

// virtualIP reports whether the data plane runs in virtual-ip host
// resolution mode.
func (r *Reconciler) virtualIP() bool {
	return r.UprobeManager != nil && r.UprobeManager.VirtualIPEnabled()
}

// attachDNSRewrite attaches the virtual IP DNS rewrite in the pod's network
// namespace, found through any process in the pod's cgroup: its sandbox's
// runs before any container. It returns false when it should be retried.
func (r *Reconciler) attachDNSRewrite(pod *corev1.Pod, name string) bool {
	if !r.virtualIP() || pod.Spec.HostNetwork {
		return true
	}
	podCgroup, err := cgroups.FindPodCgroupPath(r.CgroupRoot, string(pod.UID))
	if err != nil {
		r.Log.Debugw("pod cgroup not found yet", "pod", name, "err", err)
		return false
	}
	pids, err := cgroups.ReadCgroupTreeProcs(podCgroup)
	if err != nil || len(pids) == 0 {
		r.Log.Debugw("no process in the pod cgroup yet", "pod", name, "path", podCgroup, "err", err)
		return false
	}
	if err := r.UprobeManager.AttachPodDNSRewrite(string(pod.UID), name, pids); err != nil {
		logging.Tracew(r.Log, "could not attach the DNS rewrite yet", "pod", name, "err", err)
		return false
	}
	return true
}

// podIPs returns the pod's addresses, or none for a pod in the host network
// namespace (its address is the node's).
func podIPs(pod *corev1.Pod) []netip.Addr {
	if pod.Spec.HostNetwork {
		return nil
	}
	ips := pod.Status.PodIPs
	if len(ips) == 0 && pod.Status.PodIP != "" {
		ips = []corev1.PodIP{{IP: pod.Status.PodIP}}
	}
	var out []netip.Addr
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip.IP); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
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

	// Untrack the cgroups: this stops exec/exit tracking for them and
	// detaches the uprobes attached for their processes.
	if r.UprobeManager != nil {
		r.UprobeManager.UnbindPod(uid)
		r.UprobeManager.DetachPodDNSRewrite(uid)
		for cgroupID := range cgroupIDs {
			if err := r.UprobeManager.UntrackCgroup(cgroupID); err != nil {
				r.Log.Debugw("failed to untrack cgroup", "cgroupID", cgroupID, "err", err)
			}
		}
	}

	// Remove the pod from our tracking.
	delete(r.trackedPods, uid)
	delete(r.podKeyToUID, namespacedName)
	r.mu.Unlock()
	r.Log.Infow("stopped tracking pod", "pod", namespacedName, "uid", uid, "cgroupCount", len(cgroupIDs))

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
				r.Log.Debugw("could not find container cgroup", "container", status.Name, "err", err)
				continue
			}

			cgroupID, err := cgroups.GetCgroupInodeFromPath(containerCgroupPath)
			if err != nil {
				r.Log.Debugw("could not get cgroup inode", "container", status.Name, "path", containerCgroupPath, "err", err)
				continue
			}

			logging.Tracew(r.Log, "found container cgroup", "container", status.Name, "cgroupPath", containerCgroupPath, "cgroupID", cgroupID)
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
