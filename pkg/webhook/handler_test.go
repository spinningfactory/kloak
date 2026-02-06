package webhook

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dhia/bouncer/pkg/storage"
)

func TestIsEnabled(t *testing.T) {
	h := &Handler{}

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
			result := h.isEnabled(tc.pod)
			if result != tc.expected {
				t.Errorf("isEnabled() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestInjectEnvoySidecar(t *testing.T) {
	h := &Handler{}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "myapp:latest"},
			},
		},
	}

	h.injectEnvoySidecar(pod)

	// Check sidecar was added
	if len(pod.Spec.Containers) != 2 {
		t.Fatalf("Expected 2 containers, got %d", len(pod.Spec.Containers))
	}

	sidecar := pod.Spec.Containers[1]
	if sidecar.Name != "envoy-sidecar" {
		t.Errorf("Expected sidecar name 'envoy-sidecar', got '%s'", sidecar.Name)
	}

	// Check volumes were added
	if len(pod.Spec.Volumes) != 1 {
		t.Errorf("Expected 1 volumes, got %d", len(pod.Spec.Volumes))
	}
}

func TestMountRootCA(t *testing.T) {
	h := &Handler{}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "myapp:latest"},
			},
		},
	}

	h.mountRootCA(pod)

	// Check volume was added
	if len(pod.Spec.Volumes) != 1 {
		t.Fatalf("Expected 1 volume, got %d", len(pod.Spec.Volumes))
	}

	if pod.Spec.Volumes[0].Name != "bouncer-data" {
		t.Errorf("Expected volume name 'bouncer-data', got '%s'", pod.Spec.Volumes[0].Name)
	}

	// Check mount was added to app container
	if len(pod.Spec.Containers[0].VolumeMounts) != 1 {
		t.Fatalf("Expected 1 volume mount, got %d", len(pod.Spec.Containers[0].VolumeMounts))
	}

	mount := pod.Spec.Containers[0].VolumeMounts[0]
	if mount.MountPath != "/etc/bouncer-data" {
		t.Errorf("Expected mount path '/etc/bouncer-data', got '%s'", mount.MountPath)
	}
}

func TestHashEnvVars(t *testing.T) {
	store := storage.NewMemory()
	h := &Handler{
		storage:    store,
		envsToHash: []string{"API_KEY", "SECRET"},
	}

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: "myapp:latest",
					Env: []corev1.EnvVar{
						{Name: "API_KEY", Value: "secret-key-123"},
						{Name: "DEBUG", Value: "true"},
						{Name: "SECRET", Value: "my-secret"},
					},
				},
			},
		},
	}

	h.hashEnvVars(context.Background(), pod, "test/pod")

	// Check API_KEY was hashed (starts with bouncer:)
	env := pod.Spec.Containers[0].Env
	if env[0].Value == "secret-key-123" {
		t.Error("API_KEY should have been hashed")
	}
	if env[0].Value[:8] != "bouncer:" {
		t.Errorf("Hashed value should start with 'bouncer:', got '%s'", env[0].Value)
	}

	// Check DEBUG was NOT hashed
	if env[1].Value != "true" {
		t.Error("DEBUG should not have been hashed")
	}

	// Check SECRET was hashed
	if env[2].Value == "my-secret" {
		t.Error("SECRET should have been hashed")
	}

	// Verify storage has the mappings
	all, _ := store.List(context.Background())
	if len(all) != 2 {
		t.Errorf("Expected 2 stored mappings, got %d", len(all))
	}
}
