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
	"k8s.io/apimachinery/pkg/types"
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

	// A Pending pod is checked every sandboxPoll for its
	// sandbox, to attach the DNS rewrite before its containers start; once
	// pending for sandboxPollFor (a long image pull, a CNI failure), every
	// sandboxPollSlow.
	sandboxPoll     = 100 * time.Millisecond
	sandboxPollFor  = 30 * time.Second
	sandboxPollSlow = 5 * time.Second

	// sandboxPodLookupTimeout bounds PrepareSandbox's read of a pod the
	// cache does not have yet: the container runtime waits for it.
	sandboxPodLookupTimeout = time.Second
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
	// APIReader reads a pod from the API server when the cache does not have
	// it yet (PrepareSandbox); nil: cache only.
	APIReader client.Reader

	mu sync.RWMutex
	// trackedPods maps pod UID -> set of cgroup IDs (one per container).
	// Value is true if uprobes were successfully attached, false if attachment
	// failed (e.g. libssl not loaded yet) and should be retried.
	trackedPods map[string]map[uint64]bool

	// exitedCgroups maps pod UID -> the cgroups of its containers that
	// exited (init containers that completed, containers that restarted).
	// They are untracked when they exit, but for the pod's network
	// namespace recorded for them, released when the pod goes.
	exitedCgroups map[string]map[uint64]struct{}

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
		exitedCgroups: make(map[string]map[uint64]struct{}),
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

	uid := string(pod.UID)
	addrs := podIPs(pod)

	switch pod.Status.Phase {
	case corev1.PodRunning, corev1.PodPending:
	case corev1.PodSucceeded, corev1.PodFailed:
		// Every container of the pod has exited for good.
		r.mu.RLock()
		_, tracked := r.trackedPods[uid]
		r.mu.RUnlock()
		if tracked {
			return r.handleDelete(uid, req.String())
		}
		return ctrl.Result{}, nil
	default:
		log.Debugw("pod not running", "phase", pod.Status.Phase)
		return ctrl.Result{}, nil
	}
	pending := pod.Status.Phase == corev1.PodPending

	// Attach the DNS rewrite as soon as the pod's sandbox runs, so that its
	// containers, init containers first, find it in place, and bind the pod
	// at the sandbox's address (its status reports it only later). With NRI
	// the runtime already had it attached while creating the sandbox
	// (PrepareSandbox), and this finds it in place; without NRI, a lookup
	// made before gets the real addresses. For a running pod, this covers
	// pods running before the controller started, and a pod whose sandbox
	// was recreated (a new netns).
	if !pod.Spec.HostNetwork && r.virtualIP() {
		// Tracked first, for handleDelete to detach it.
		r.trackPod(uid, req.String())
	}
	netnsAddrs, dnsAttached := r.attachDNSRewrite(pod, req.String())
	if len(addrs) == 0 {
		addrs = netnsAddrs
	}
	refs := k8ssecrets.PodSecretRefs(pod)
	if pending {
		if !dnsAttached {
			poll := sandboxPoll
			if time.Since(pod.CreationTimestamp.Time) > sandboxPollFor {
				poll = sandboxPollSlow
			}
			return ctrl.Result{RequeueAfter: poll}, nil
		}
		// A pending pod's init containers run: they are attached below as a
		// running pod's containers are. Until one runs, only the pod's
		// network is bound. Its status changes when one starts, which
		// reconciles the pod again.
		if !hasRunningContainer(pod) {
			if !pod.Spec.HostNetwork && r.virtualIP() {
				r.UprobeManager.BindPodNetwork(uid, req.String(), addrs, refs)
			}
			return ctrl.Result{}, nil
		}
	}

	containers, err := r.getContainerCgroups(pod)
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
	existingCgroups := r.trackedPods[uid]
	if existingCgroups == nil {
		existingCgroups = make(map[uint64]bool)
	}

	// Collect cgroups that need uprobe attachment:
	// - New cgroups not yet tracked
	// - Previously tracked cgroups where attachment failed (value=false)
	for cgroupID, c := range containers {
		attached, tracked := existingCgroups[cgroupID]
		if !tracked {
			existingCgroups[cgroupID] = false // tracked but not yet attached
			delete(r.exitedCgroups[uid], cgroupID)
			log.Infow("tracking container cgroup", "cgroupID", cgroupID, "container", c.name)
			needsAttach = append(needsAttach, cgroupID)
		} else if !attached {
			// Retry attachment (e.g. libssl not loaded on first attempt)
			needsAttach = append(needsAttach, cgroupID)
		}
	}

	// A cgroup no longer listed is a container that exited: an init
	// container that completed, or a container that restarted (in a new
	// cgroup). It is untracked now, except for the pod's network namespace
	// recorded for it, released with the pod: a later container's tc attach
	// finds the pod's tc program in place through it instead of attaching a
	// second one.
	var exitedNow []uint64
	for cgroupID := range existingCgroups {
		if _, ok := containers[cgroupID]; ok {
			continue
		}
		delete(existingCgroups, cgroupID)
		if r.exitedCgroups == nil {
			r.exitedCgroups = make(map[string]map[uint64]struct{})
		}
		if r.exitedCgroups[uid] == nil {
			r.exitedCgroups[uid] = make(map[uint64]struct{})
		}
		r.exitedCgroups[uid][cgroupID] = struct{}{}
		exitedNow = append(exitedNow, cgroupID)
	}

	r.trackedPods[uid] = existingCgroups
	r.podKeyToUID[req.String()] = uid
	r.mu.Unlock()

	for _, cgroupID := range exitedNow {
		log.Infow("container exited, untracking its cgroup", "cgroupID", cgroupID)
		if r.UprobeManager != nil {
			if err := r.UprobeManager.UntrackExitedCgroup(cgroupID); err != nil {
				log.Debugw("failed to untrack the cgroup of an exited container", "cgroupID", cgroupID, "err", err)
			}
		}
	}

	// Bind before attaching, so that by the time the uprobes fire this pod's
	// containers can redeem exactly the secrets its spec references. Rebinding
	// on every reconcile picks up containers restarted with a new cgroup.
	if r.UprobeManager != nil {
		ids := make([]uint64, 0, len(containers))
		for id := range containers {
			ids = append(ids, id)
		}
		r.UprobeManager.BindPodSecrets(uid, req.String(), addrs, ids, refs)
	}

	// Attach uprobes outside the lock — this involves filesystem I/O.
	for _, cgroupID := range needsAttach {
		c := containers[cgroupID]
		pid, ok := r.attachUprobesToCgroup(cgroupID, c)
		if !ok {
			continue
		}
		r.mu.Lock()
		if tracked := r.trackedPods[uid]; tracked != nil {
			tracked[cgroupID] = true // mark as successfully attached
		}
		r.mu.Unlock()

		// Register the cgroup for exec/exit tracepoint tracking so new
		// processes spawned inside the container are automatically detected.
		if err := r.UprobeManager.TrackCgroup(cgroupID, c.path); err != nil {
			log.Errorw("failed to track cgroup for exec events", "error", err, "cgroupID", cgroupID)
		}
		// Record which netns this cgroup belongs to, so UntrackCgroup
		// can clean up the pinned netns fd and allow inode reuse.
		r.UprobeManager.RecordCgroupNetns(cgroupID, pid)
	}

	// If any cgroups still need attachment, requeue to retry later.
	// This handles runtimes like Python where libssl loads lazily.
	r.mu.RLock()
	needsRetry := !dnsAttached
	if tracked := r.trackedPods[uid]; tracked != nil {
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

// attachUprobesToCgroup attaches the TLS uprobes for the processes of a
// container, c with cgroup ID cgroupID. It returns one of the container's
// PIDs the attach succeeded for, and whether it succeeded for any.
func (r *Reconciler) attachUprobesToCgroup(cgroupID uint64, c containerCgroup) (int, bool) {
	if r.UprobeManager == nil {
		return 0, false
	}

	logging.Tracew(r.Log, "trying to attach uprobes to container", "cgroup", cgroupID, "container", c.name)

	pids, err := cgroups.ReadCgroupProcs(c.path)
	if err != nil {
		// The container exited since its status was read.
		r.Log.Debugw("failed to read cgroup.procs", "error", err, "path", c.path)
		return 0, false
	}
	if len(pids) == 0 {
		r.Log.Debugw("no PIDs found in cgroup.procs", "path", c.path)
		return 0, false
	}

	// Attempt to attach uprobes to every PID in the cgroup.
	// Containers may run multiple processes; we probe all of them so that
	// whichever process makes TLS calls is instrumented. AttachTLS skips
	// PIDs that have no compatible TLS symbols.
	attachedPid := 0
	for _, pid := range pids {
		if err := r.UprobeManager.AttachTLS(pid, cgroupID); err != nil {
			logging.Tracew(r.Log, "could not attach TLS uprobes to pid", "pid", pid, "container", c.name, "err", err)
			continue
		}
		r.Log.Infow("Successfully attached TLS uprobes", "pid", pid, "container", c.name)
		if attachedPid == 0 {
			attachedPid = pid
		}
	}
	return attachedPid, attachedPid != 0
}

// trackPod records a pod as tracked, for handleDelete to release what is
// attached for it.
func (r *Reconciler) trackPod(uid, key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trackedPods[uid] == nil {
		r.trackedPods[uid] = make(map[uint64]bool)
	}
	r.podKeyToUID[key] = uid
}

// virtualIP reports whether there is a data plane to attach the virtual IP
// DNS rewrite with.
func (r *Reconciler) virtualIP() bool {
	return r.UprobeManager != nil
}

// Sandbox is a pod sandbox the container runtime is creating, as it reports
// it over NRI.
type Sandbox struct {
	ID        string
	UID       string
	Namespace string
	Name      string
	// Annotations are the pod's (the kubelet passes them to the sandbox).
	Annotations map[string]string
	// NetnsPath is the sandbox's network namespace as a path this process
	// can open; "" when the runtime does not report one (host network).
	NetnsPath string
	// IPs are the pod's addresses, when the runtime reports them.
	IPs []netip.Addr
}

// PrepareSandbox attaches the virtual IP DNS rewrite in a kloak pod's
// network namespace and binds the pod at its addresses, while the container
// runtime creates the pod's sandbox or one of its containers (NRI): the
// runtime waits for it, so the rewrite is in place before any container of
// the pod resolves a name. It reports whether the pod is prepared; when it
// is not (no NRI, or a failure), the reconciler attaches the rewrite by
// polling the Pending pod, which leaves a short window at pod start.
func (r *Reconciler) PrepareSandbox(ctx context.Context, sb *Sandbox) bool {
	// Most sandboxes are not kloak pods: no API read for them.
	if !r.virtualIP() || sb.Annotations[AnnotationEnabled] != "true" || sb.NetnsPath == "" {
		return false
	}
	name := sb.Namespace + "/" + sb.Name
	pod, err := r.sandboxPod(ctx, sb)
	if err != nil {
		r.Log.Debugw("pod of a sandbox being created not found; the reconciler attaches the DNS rewrite when it sees the pod",
			"pod", name, "sandbox", sb.ID, "error", err)
		return false
	}
	// The sandbox is on this node: the runtime creating it is this node's,
	// whatever the cache's copy of the pod says yet.
	if !r.isEnabled(pod) || pod.Spec.HostNetwork {
		return false
	}

	r.trackPod(string(pod.UID), name)

	netnsAddrs, err := r.UprobeManager.AttachPodDNSRewriteNetns(string(pod.UID), name, sb.NetnsPath)
	if err != nil {
		logging.Tracew(r.Log, "could not attach the DNS rewrite at sandbox creation", "pod", name, "sandbox", sb.ID, "err", err)
		return false
	}
	addrs := sb.IPs
	if len(addrs) == 0 {
		addrs = netnsAddrs
	}
	r.UprobeManager.BindPodNetwork(string(pod.UID), name, addrs, k8ssecrets.PodSecretRefs(pod))
	r.Log.Infow("DNS rewrite in place at sandbox creation (NRI)", "pod", name, "sandbox", sb.ID, "addrs", addrs)
	return true
}

// sandboxPod returns the pod a sandbox is created for: from the cache, or,
// when the cache does not have it yet, from the API server.
func (r *Reconciler) sandboxPod(ctx context.Context, sb *Sandbox) (*corev1.Pod, error) {
	nn := types.NamespacedName{Namespace: sb.Namespace, Name: sb.Name}
	pod := &corev1.Pod{}
	if err := r.Get(ctx, nn, pod); err == nil && string(pod.UID) == sb.UID {
		return pod, nil
	}
	if r.APIReader == nil {
		return nil, fmt.Errorf("pod %s (uid %s) not in the cache", nn, sb.UID)
	}
	ctx, cancel := context.WithTimeout(ctx, sandboxPodLookupTimeout)
	defer cancel()
	pod = &corev1.Pod{}
	if err := r.APIReader.Get(ctx, nn, pod); err != nil {
		return nil, err
	}
	if string(pod.UID) != sb.UID {
		return nil, fmt.Errorf("pod %s has uid %s, the sandbox is for %s", nn, pod.UID, sb.UID)
	}
	return pod, nil
}

// attachDNSRewrite attaches the virtual IP DNS rewrite in the pod's network
// namespace, found through any process in the pod's cgroup: its sandbox's
// runs before any container. It returns the pod's IPv4 addresses as found
// in the netns, and false when it should be retried.
func (r *Reconciler) attachDNSRewrite(pod *corev1.Pod, name string) ([]netip.Addr, bool) {
	if !r.virtualIP() || pod.Spec.HostNetwork {
		return nil, true
	}
	podCgroup, err := cgroups.FindPodCgroupPath(r.CgroupRoot, string(pod.UID))
	if err != nil {
		logging.Tracew(r.Log, "pod cgroup not found yet", "pod", name, "err", err)
		return nil, false
	}
	pids, err := cgroups.ReadCgroupTreeProcs(podCgroup)
	if err != nil || len(pids) == 0 {
		logging.Tracew(r.Log, "no process in the pod cgroup yet", "pod", name, "path", podCgroup, "err", err)
		return nil, false
	}
	addrs, err := r.UprobeManager.AttachPodDNSRewrite(string(pod.UID), name, pids)
	if err != nil {
		logging.Tracew(r.Log, "could not attach the DNS rewrite yet", "pod", name, "err", err)
		return nil, false
	}
	return addrs, true
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
	exited := r.exitedCgroups[uid]

	// Untrack the cgroups: this stops exec/exit tracking for them and
	// detaches the uprobes attached for their processes. Those of the
	// containers that exited are untracked already, all but the pod's
	// network namespace recorded for them.
	if r.UprobeManager != nil {
		r.UprobeManager.UnbindPod(uid)
		r.UprobeManager.DetachPodDNSRewrite(uid)
		for cgroupID := range cgroupIDs {
			if err := r.UprobeManager.UntrackCgroup(cgroupID); err != nil {
				r.Log.Debugw("failed to untrack cgroup", "cgroupID", cgroupID, "err", err)
			}
		}
		for cgroupID := range exited {
			r.UprobeManager.ReleaseCgroupNetns(cgroupID)
		}
	}

	// Remove the pod from our tracking.
	delete(r.trackedPods, uid)
	delete(r.exitedCgroups, uid)
	delete(r.podKeyToUID, namespacedName)
	r.mu.Unlock()
	r.Log.Infow("stopped tracking pod", "pod", namespacedName, "uid", uid, "cgroupCount", len(cgroupIDs)+len(exited))

	return ctrl.Result{}, nil
}

// isEnabled checks if Kloak should process this pod.
func (r *Reconciler) isEnabled(pod *corev1.Pod) bool {
	if pod.Annotations == nil {
		return false
	}
	return pod.Annotations[AnnotationEnabled] == "true"
}

// containerCgroup is the cgroup of a running container.
type containerCgroup struct {
	path string // the cgroup's directory
	name string // the container's name, for logs
}

// hasRunningContainer reports whether the pod's status lists a running
// container, init containers included.
func hasRunningContainer(pod *corev1.Pod) bool {
	for _, statuses := range [][]corev1.ContainerStatus{pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses} {
		for i := range statuses {
			if statuses[i].ContainerID != "" && statuses[i].State.Running != nil {
				return true
			}
		}
	}
	return false
}

// getContainerCgroups returns the cgroups of the pod's running containers,
// init containers included (a pending pod's, or a running pod's sidecars),
// by cgroup ID. For cgroups v2, that is the inode number of the container's
// cgroup directory. We track container cgroups (not pod cgroups) because
// bpf_get_current_cgroup_id() returns the container's .scope cgroup, not the
// pod's .slice cgroup. A container that is not running is left out: its
// cgroup is gone, and the lookup could fall back to the pod's.
func (r *Reconciler) getContainerCgroups(pod *corev1.Pod) (map[uint64]containerCgroup, error) {
	containers := make(map[uint64]containerCgroup)

	collectFromStatuses := func(statuses []corev1.ContainerStatus) {
		for i := range statuses {
			status := &statuses[i]
			if status.ContainerID == "" || status.State.Running == nil {
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
			containers[cgroupID] = containerCgroup{path: containerCgroupPath, name: status.Name}
		}
	}

	collectFromStatuses(pod.Status.ContainerStatuses)
	collectFromStatuses(pod.Status.InitContainerStatuses)

	if len(containers) == 0 {
		return nil, fmt.Errorf("no container cgroups found for pod %s/%s", pod.Namespace, pod.Name)
	}

	return containers, nil
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
