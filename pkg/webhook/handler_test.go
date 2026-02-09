package webhook

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-logr/logr"
	"github.com/spinningfactory/kloak/pkg/storage"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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

	if pod.Spec.Volumes[0].Name != "kloak-ca" {
		t.Errorf("Expected volume name 'kloak-ca', got '%s'", pod.Spec.Volumes[0].Name)
	}

	// Check ConfigMap volume source
	if pod.Spec.Volumes[0].ConfigMap == nil {
		t.Fatal("Expected ConfigMap volume source, got nil")
	}
	if pod.Spec.Volumes[0].ConfigMap.Name != "kloak-ca-cert" {
		t.Errorf("Expected ConfigMap name 'kloak-ca-cert', got '%s'", pod.Spec.Volumes[0].ConfigMap.Name)
	}

	// Check mount was added to app container
	if len(pod.Spec.Containers[0].VolumeMounts) != 1 {
		t.Fatalf("Expected 1 volume mount, got %d", len(pod.Spec.Containers[0].VolumeMounts))
	}

	mount := pod.Spec.Containers[0].VolumeMounts[0]
	if mount.MountPath != "/etc/kloak-ca" {
		t.Errorf("Expected mount path '/etc/kloak-ca', got '%s'", mount.MountPath)
	}

	// Check SSL_CERT_FILE env var was added
	if len(pod.Spec.Containers[0].Env) != 1 {
		t.Fatalf("Expected 1 env var, got %d", len(pod.Spec.Containers[0].Env))
	}
	if pod.Spec.Containers[0].Env[0].Name != "SSL_CERT_FILE" {
		t.Errorf("Expected env var 'SSL_CERT_FILE', got '%s'", pod.Spec.Containers[0].Env[0].Name)
	}
	if pod.Spec.Containers[0].Env[0].Value != "/etc/kloak-ca/ca.crt" {
		t.Errorf("Expected SSL_CERT_FILE='/etc/kloak-ca/ca.crt', got '%s'", pod.Spec.Containers[0].Env[0].Value)
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

	// Check API_KEY was hashed (starts with kloak:)
	env := pod.Spec.Containers[0].Env
	if env[0].Value == "secret-key-123" {
		t.Error("API_KEY should have been hashed")
	}
	if env[0].Value[:6] != "kloak:" {
		t.Errorf("Hashed value should start with 'kloak:', got '%s'", env[0].Value)
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

	// Check content of one entry (optional, but good for verification)
	for _, entry := range all {
		if entry.AllowedHosts[0] != "*" {
			t.Errorf("Expected allowed host '*', got %v", entry.AllowedHosts)
		}
	}
}

func TestRewriteSecretVolumes(t *testing.T) {
	// Setup fake client
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	enabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
			Labels: map[string]string{
				"getkloak.io/enabled": "true",
			},
		},
	}

	disabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-secret",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabledSecret, disabledSecret).Build()

	// Use discard logger
	h := &Handler{
		client: fakeClient,
		log:    logr.Discard(),
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "vol-enabled",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "my-secret",
						},
					},
				},
				{
					Name: "vol-disabled",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "other-secret",
						},
					},
				},
				{
					Name: "vol-missing",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "missing-secret",
						},
					},
				},
			},
		},
	}

	err := h.rewriteSecretVolumes(context.Background(), pod, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify "my-secret" rewrote to "my-secret-kloak"
	if pod.Spec.Volumes[0].Secret.SecretName != "my-secret-kloak" {
		t.Errorf("Expected my-secret-kloak, got %s", pod.Spec.Volumes[0].Secret.SecretName)
	}

	// Verify "other-secret" stayed same
	if pod.Spec.Volumes[1].Secret.SecretName != "other-secret" {
		t.Errorf("Expected other-secret, got %s", pod.Spec.Volumes[1].Secret.SecretName)
	}
}
