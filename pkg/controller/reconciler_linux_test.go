//go:build linux

package controller

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/spinningfactory/kloak/pkg/cgroups"
)

// fakeContainerCgroup creates, under root, the cgroup directory of a
// container of a BestEffort pod as the cgroupfs driver lays it out, and
// returns its cgroup ID.
func fakeContainerCgroup(t *testing.T, root, podUID, containerID string) uint64 {
	t.Helper()
	dir := filepath.Join(root, "kubepods", "besteffort", "pod"+podUID, containerID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := cgroups.GetCgroupInodeFromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func runningStatus(name, containerID string) corev1.ContainerStatus {
	return corev1.ContainerStatus{Name: name, ContainerID: "containerd://" + containerID,
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
}

func terminatedStatus(name, containerID string) corev1.ContainerStatus {
	return corev1.ContainerStatus{Name: name, ContainerID: "containerd://" + containerID,
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}}
}

// TestReconcileInitContainer follows a pod through its init container: the
// init container is tracked while the pod is pending; once it completed and
// the app container runs, the app container's cgroup is tracked and the
// init container's is kept until the pod goes; once the pod succeeded,
// nothing of it is tracked.
func TestReconcileInitContainer(t *testing.T) {
	root := t.TempDir()
	const uid = "job-uid"
	initID := fakeContainerCgroup(t, root, uid, "init1")
	appID := fakeContainerCgroup(t, root, uid, "app1")

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "default", UID: uid,
			Annotations: map[string]string{AnnotationEnabled: "true"}},
		Status: corev1.PodStatus{
			Phase:                 corev1.PodPending,
			InitContainerStatuses: []corev1.ContainerStatus{runningStatus("clone", "init1")},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "app",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "PodInitializing"}}}},
		},
	}
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(pod).WithStatusSubresource(&corev1.Pod{}).Build()
	r := NewReconciler(c, zap.NewNop().Sugar(), testScheme(), nil, root, "")
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "job"}}

	reconcile := func() ctrl.Result {
		t.Helper()
		res, err := r.Reconcile(ctx, req)
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		return res
	}
	setStatus := func(s corev1.PodStatus) {
		t.Helper()
		cur := &corev1.Pod{}
		if err := c.Get(ctx, req.NamespacedName, cur); err != nil {
			t.Fatal(err)
		}
		cur.Status = s
		if err := c.Status().Update(ctx, cur); err != nil {
			t.Fatal(err)
		}
	}
	state := func() (tracked map[uint64]bool, exited map[uint64]struct{}) {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return maps.Clone(r.trackedPods[uid]), maps.Clone(r.exitedCgroups[uid])
	}

	// Pending, the init container runs: tracked. Without a data plane it is
	// not attached, which is retried.
	res := reconcile()
	tracked, exited := state()
	if _, ok := tracked[initID]; !ok || len(tracked) != 1 || len(exited) != 0 {
		t.Fatalf("pending pod: tracked %v, exited %v; want the init container's cgroup %d tracked", tracked, exited, initID)
	}
	if res.RequeueAfter == 0 {
		t.Error("the attach of the init container is not retried")
	}

	// The init container completed and the app container runs.
	setStatus(corev1.PodStatus{
		Phase:                 corev1.PodRunning,
		InitContainerStatuses: []corev1.ContainerStatus{terminatedStatus("clone", "init1")},
		ContainerStatuses:     []corev1.ContainerStatus{runningStatus("app", "app1")},
	})
	reconcile()
	tracked, exited = state()
	if _, ok := tracked[appID]; !ok || len(tracked) != 1 {
		t.Errorf("running pod: tracked %v, want only the app container's cgroup %d", tracked, appID)
	}
	if _, ok := exited[initID]; !ok || len(exited) != 1 {
		t.Errorf("running pod: exited %v, want the init container's cgroup %d", exited, initID)
	}

	// The pod succeeded: nothing of it is tracked.
	setStatus(corev1.PodStatus{
		Phase:                 corev1.PodSucceeded,
		InitContainerStatuses: []corev1.ContainerStatus{terminatedStatus("clone", "init1")},
		ContainerStatuses:     []corev1.ContainerStatus{terminatedStatus("app", "app1")},
	})
	if res := reconcile(); res.RequeueAfter != 0 {
		t.Errorf("succeeded pod requeued after %v", res.RequeueAfter)
	}
	if n := r.GetTrackedPodCount(); n != 0 {
		t.Errorf("%d pods tracked after the pod succeeded", n)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.exitedCgroups) != 0 || len(r.podKeyToUID) != 0 {
		t.Errorf("left after the pod succeeded: exited %v, keys %v", r.exitedCgroups, r.podKeyToUID)
	}
}

// TestGetContainerCgroups checks which containers' cgroups are listed: the
// running ones, init containers included (a sidecar), not a container that
// terminated or waits to restart, whose cgroup is gone.
func TestGetContainerCgroups(t *testing.T) {
	root := t.TempDir()
	const uid = "pod-uid"
	appID := fakeContainerCgroup(t, root, uid, "app1")
	sidecarID := fakeContainerCgroup(t, root, uid, "sidecar1")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default", UID: uid},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			InitContainerStatuses: []corev1.ContainerStatus{
				terminatedStatus("setup", "setup1"),
				runningStatus("sidecar", "sidecar1"),
			},
			ContainerStatuses: []corev1.ContainerStatus{
				runningStatus("app", "app1"),
				{Name: "crashing", ContainerID: "containerd://crash1",
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}},
			},
		},
	}
	r := NewReconciler(nil, zap.NewNop().Sugar(), testScheme(), nil, root, "")
	got, err := r.getContainerCgroups(pod)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint64]containerCgroup{
		appID:     {path: filepath.Join(root, "kubepods", "besteffort", "pod"+uid, "app1"), name: "app"},
		sidecarID: {path: filepath.Join(root, "kubepods", "besteffort", "pod"+uid, "sidecar1"), name: "sidecar"},
	}
	if !maps.Equal(got, want) {
		t.Errorf("getContainerCgroups = %v, want %v", got, want)
	}
}
