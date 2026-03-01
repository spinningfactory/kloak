package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	}

	// Add a tracked pod with multiple container cgroups
	r.trackedPods["test-pod-uid"] = map[uint64]bool{12345: true, 67890: true}

	// Handle delete
	_, err := r.handleDelete("test-pod-uid")
	if err != nil {
		t.Fatalf("handleDelete failed: %v", err)
	}

	// Verify pod is no longer tracked
	if _, exists := r.trackedPods["test-pod-uid"]; exists {
		t.Error("Pod should no longer be tracked")
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
