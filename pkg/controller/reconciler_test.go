package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsEnabled(t *testing.T) {
	r := &Reconciler{}

	tests := []struct {
		name     string
		pod      *corev1.Pod
		expected bool
	}{
		{
			name:     "no annotations",
			pod:      &corev1.Pod{},
			expected: false,
		},
		{
			name: "enabled=true",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationEnabled: "true",
					},
				},
			},
			expected: true,
		},
		{
			name: "enabled=false",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationEnabled: "false",
					},
				},
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := r.isEnabled(tc.pod)
			if result != tc.expected {
				t.Errorf("isEnabled() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestHandleDelete(t *testing.T) {
	r := &Reconciler{
		trackedPods: make(map[string]map[uint64]bool),
		podKeyToUID: make(map[string]string),
	}

	// Add a tracked pod with multiple container cgroups
	r.trackedPods["test-pod-uid"] = map[uint64]bool{12345: true, 67890: true}
	r.podKeyToUID["default/test-pod"] = "test-pod-uid"

	// Handle delete
	_, err := r.handleDelete("test-pod-uid", "default/test-pod")
	if err != nil {
		t.Fatalf("handleDelete failed: %v", err)
	}

	// Verify pod is no longer tracked
	if _, exists := r.trackedPods["test-pod-uid"]; exists {
		t.Error("Pod should no longer be tracked")
	}

	// Verify reverse map is also cleaned up
	if _, exists := r.podKeyToUID["default/test-pod"]; exists {
		t.Error("podKeyToUID entry should be removed on delete")
	}
}

func TestGetTrackedPodCount(t *testing.T) {
	r := &Reconciler{
		trackedPods: make(map[string]map[uint64]bool),
	}

	if r.GetTrackedPodCount() != 0 {
		t.Error("Expected 0 tracked pods initially")
	}

	r.trackedPods["pod1"] = map[uint64]bool{111: true}
	r.trackedPods["pod2"] = map[uint64]bool{222: true, 333: true}

	if r.GetTrackedPodCount() != 2 {
		t.Errorf("Expected 2 tracked pods, got %d", r.GetTrackedPodCount())
	}
}

func TestNewReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := NewReconciler(c, logr.Discard(), scheme, nil, "", "node-1", nil)

	if r == nil {
		t.Fatal("NewReconciler returned nil")
	}
	if r.CgroupRoot != CgroupBasePath {
		t.Errorf("expected default cgroup root %q, got %q", CgroupBasePath, r.CgroupRoot)
	}
	if r.NodeName != "node-1" {
		t.Errorf("expected node name 'node-1', got %q", r.NodeName)
	}
	if r.trackedPods == nil {
		t.Error("trackedPods map not initialized")
	}
	if r.podKeyToUID == nil {
		t.Error("podKeyToUID map not initialized")
	}
}

func TestNewReconciler_CustomCgroupRoot(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := NewReconciler(c, logr.Discard(), scheme, nil, "/custom/cgroup", "", nil)

	if r.CgroupRoot != "/custom/cgroup" {
		t.Errorf("expected custom cgroup root, got %q", r.CgroupRoot)
	}
}

func TestReconcile_PodNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewReconciler(c, logr.Discard(), scheme, nil, "", "", nil)

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "missing", Namespace: "default"}}
	result, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Fatalf("should not error on NotFound: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("should not requeue for missing pod")
	}
}

func TestReconcile_DisabledPod(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "disabled-pod", Namespace: "default",
			UID: "disabled-uid",
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	r := NewReconciler(c, logr.Discard(), scheme, nil, "", "", nil)

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "disabled-pod", Namespace: "default"}}
	result, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("should not requeue for disabled pod")
	}
	if r.GetTrackedPodCount() != 0 {
		t.Error("disabled pod should not be tracked")
	}
}

func TestReconcile_EnabledPodNotRunning(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pending-pod", Namespace: "default",
			Annotations: map[string]string{AnnotationEnabled: "true"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	r := NewReconciler(c, logr.Discard(), scheme, nil, "", "", nil)

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "pending-pod", Namespace: "default"}}
	result, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("should not requeue for pending pod")
	}
}

func TestReconcile_WrongNode(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "other-node-pod", Namespace: "default",
			Annotations: map[string]string{AnnotationEnabled: "true"},
		},
		Spec:   corev1.PodSpec{NodeName: "node-2"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	r := NewReconciler(c, logr.Discard(), scheme, nil, "", "node-1", nil)

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "other-node-pod", Namespace: "default"}}
	result, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("should not requeue for pod on different node")
	}
	if r.GetTrackedPodCount() != 0 {
		t.Error("pod on different node should not be tracked")
	}
}

func TestHandleDelete_NotTracked(t *testing.T) {
	r := &Reconciler{
		trackedPods: make(map[string]map[uint64]bool),
		podKeyToUID: make(map[string]string),
		Log:         logr.Discard(),
	}

	result, err := r.handleDelete("unknown-uid", "default/unknown")
	if err != nil {
		t.Fatalf("handleDelete failed: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("should not requeue for untracked pod")
	}
}

func TestReconcile_EnabledRunningPodNoCgroups(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "running-pod", Namespace: "default",
			Annotations: map[string]string{AnnotationEnabled: "true"},
			UID:         "running-uid",
		},
		Spec: corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "app",
					ContainerID: "containerd://abc123def456",
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	r := NewReconciler(c, logr.Discard(), scheme, nil, "/nonexistent/cgroup", "node-1", nil)

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "running-pod", Namespace: "default"}}
	result, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Fatalf("reconcile should not error: %v", err)
	}
	// Should requeue because cgroups not found
	// The reconciler uses Requeue: true when cgroups aren't available yet.
	// We verify the result is non-zero (either Requeue or RequeueAfter set).
	if result.RequeueAfter == 0 && !result.Requeue { //nolint:staticcheck // Requeue is deprecated but still used in reconciler
		t.Error("should requeue when cgroups not available")
	}
}

func TestReconcile_DisableRemovesTracking(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Pod exists but is not annotated as enabled
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "was-tracked", Namespace: "default",
			UID: "was-tracked-uid",
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	r := NewReconciler(c, logr.Discard(), scheme, nil, "", "", nil)

	// Pre-populate as if it was previously tracked
	r.trackedPods["was-tracked-uid"] = map[uint64]bool{999: true}
	r.podKeyToUID["default/was-tracked"] = "was-tracked-uid"

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "was-tracked", Namespace: "default"}}
	_, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if r.GetTrackedPodCount() != 0 {
		t.Error("previously tracked pod should be removed when disabled")
	}
}

func TestReconcile_DeleteTrackedPod(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// No pod in the cluster (simulates deletion)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewReconciler(c, logr.Discard(), scheme, nil, "", "", nil)

	// Pre-populate tracking state
	r.trackedPods["deleted-uid"] = map[uint64]bool{12345: true}
	r.podKeyToUID["default/deleted-pod"] = "deleted-uid"

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "deleted-pod", Namespace: "default"}}
	_, err := r.Reconcile(context.Background(), req)

	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if r.GetTrackedPodCount() != 0 {
		t.Error("deleted pod should be removed from tracking")
	}
	if _, exists := r.podKeyToUID["default/deleted-pod"]; exists {
		t.Error("podKeyToUID should be cleaned up")
	}
}
