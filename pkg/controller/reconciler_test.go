package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// MockCgroupManager is a mock implementation for testing.
type MockCgroupManager struct {
	added   []uint64
	removed []uint64
}

func (m *MockCgroupManager) AddCgroup(cgroupID uint64) error {
	m.added = append(m.added, cgroupID)
	return nil
}

func (m *MockCgroupManager) RemoveCgroup(cgroupID uint64) error {
	m.removed = append(m.removed, cgroupID)
	return nil
}

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
	mgr := &MockCgroupManager{}
	r := &Reconciler{
		CgroupManager: mgr,
		trackedPods:   make(map[string]uint64),
	}

	// Add a tracked pod
	r.trackedPods["test-pod-uid"] = 12345

	// Handle delete
	_, err := r.handleDelete("test-pod-uid")
	if err != nil {
		t.Fatalf("handleDelete failed: %v", err)
	}

	// Verify cgroup was removed
	if len(mgr.removed) != 1 || mgr.removed[0] != 12345 {
		t.Errorf("Expected cgroup 12345 to be removed, got %v", mgr.removed)
	}

	// Verify pod is no longer tracked
	if _, exists := r.trackedPods["test-pod-uid"]; exists {
		t.Error("Pod should no longer be tracked")
	}
}

func TestGetTrackedPodCount(t *testing.T) {
	r := &Reconciler{
		trackedPods: make(map[string]uint64),
	}

	if r.GetTrackedPodCount() != 0 {
		t.Error("Expected 0 tracked pods initially")
	}

	r.trackedPods["pod1"] = 111
	r.trackedPods["pod2"] = 222

	if r.GetTrackedPodCount() != 2 {
		t.Errorf("Expected 2 tracked pods, got %d", r.GetTrackedPodCount())
	}
}

func TestFindCgroupPath(t *testing.T) {
	r := &Reconciler{}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID: types.UID("abc-123-def"),
		},
	}

	// This test just verifies the function doesn't panic
	// Actual cgroup paths won't exist in test environment
	_, err := r.findCgroupPath(pod, "container123")
	if err == nil {
		t.Log("Cgroup path found (unexpected in test env, but OK)")
	} else {
		t.Log("Cgroup path not found (expected in test env)")
	}
}
