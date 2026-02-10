package webhook

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsEnabled(t *testing.T) {
	// Setup fake client with namespaces and workloads
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	nsDefault := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	nsEnabled := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "enabled-ns",
			Labels: map[string]string{
				AnnotationEnabled: "true",
			},
		},
	}

	// Workload objects for inheritance testing
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "enabled-deploy",
			Namespace: "default",
			Labels: map[string]string{
				AnnotationEnabled: "true",
			},
		},
	}

	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "enabled-deploy-rs",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "enabled-deploy",
				},
			},
		},
	}

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "enabled-ds",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationEnabled: "true",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nsDefault, nsEnabled, deployment, rs, ds).Build()

	h := &Handler{
		client: fakeClient,
		log:    logr.Discard(),
	}

	tests := []struct {
		name      string
		pod       *corev1.Pod
		namespace string
		expected  bool
	}{
		{
			name:      "no annotations, default ns",
			pod:       &corev1.Pod{},
			namespace: "default",
			expected:  false,
		},
		{
			name: "explicit enabled=true",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationEnabled: "true",
					},
				},
			},
			namespace: "default",
			expected:  true,
		},
		{
			name: "explicit enabled=false",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationEnabled: "false",
					},
				},
			},
			namespace: "default",
			expected:  false,
		},
		{
			name:      "inheritance from enabled namespace",
			pod:       &corev1.Pod{},
			namespace: "enabled-ns",
			expected:  true,
		},
		{
			name: "disabled pod in enabled namespace",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationEnabled: "false",
					},
				},
			},
			namespace: "enabled-ns",
			expected:  false,
		},
		{
			name: "inheritance from deployment (via RS)",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "ReplicaSet",
							Name: "enabled-deploy-rs",
						},
					},
				},
			},
			namespace: "default",
			expected:  true,
		},
		{
			name: "inheritance from daemonset",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "DaemonSet",
							Name: "enabled-ds",
						},
					},
				},
			},
			namespace: "default",
			expected:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := h.isEnabled(context.Background(), tc.pod, tc.namespace)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
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
	// Setup fake client with CA secret
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kloak-ca",
			Namespace: "kloak-system",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("FAKE-CA-CERT"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(caSecret).Build()

	h := &Handler{
		client:          fakeClient,
		log:             logr.Discard(),
		systemNamespace: "kloak-system",
	}

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "myapp:latest"},
			},
		},
	}

	h.mountRootCA(pod)

	// Check shared volume was added
	if len(pod.Spec.Volumes) != 1 {
		t.Fatalf("Expected 1 volume, got %d", len(pod.Spec.Volumes))
	}

	if pod.Spec.Volumes[0].Name != "kloak-ca-vol" {
		t.Errorf("Expected volume name 'kloak-ca-vol', got '%s'", pod.Spec.Volumes[0].Name)
	}

	// Check EmptyDir volume source
	if pod.Spec.Volumes[0].EmptyDir == nil {
		t.Fatal("Expected EmptyDir volume source, got nil")
	}

	// Check Init Container was added
	if len(pod.Spec.InitContainers) != 1 {
		t.Fatalf("Expected 1 init container, got %d", len(pod.Spec.InitContainers))
	}
	initContainer := pod.Spec.InitContainers[0]
	if initContainer.Image != "busybox:1.36" {
		t.Errorf("Expected init container image 'busybox:1.36', got '%s'", initContainer.Image)
	}
	// Check Env var in init container
	foundEnv := false
	for _, env := range initContainer.Env {
		if env.Name == "CA_PEM" && env.Value == "FAKE-CA-CERT" {
			foundEnv = true
			break
		}
	}
	if !foundEnv {
		t.Error("Init container missing CA_PEM env var with correct value")
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
