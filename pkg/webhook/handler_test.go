package webhook

import (
	"context"
	"strings"
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

func TestGetCA(t *testing.T) {
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

	cert, err := h.getCA(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert != "FAKE-CA-CERT" {
		t.Errorf("Expected cert 'FAKE-CA-CERT', got '%s'", cert)
	}
}

func TestInjectInitContainer(t *testing.T) {
	h := &Handler{}
	pod := &corev1.Pod{}
	caCert := "FAKE-CA-CERT"

	h.injectInitContainer(pod, caCert)

	if len(pod.Spec.InitContainers) != 1 {
		t.Fatalf("Expected 1 init container, got %d", len(pod.Spec.InitContainers))
	}
	initContainer := pod.Spec.InitContainers[0]
	if initContainer.Image != JavaInitContainerImage {
		t.Errorf("Expected image '%s', got '%s'", JavaInitContainerImage, initContainer.Image)
	}

	// Command should contain keytool
	cmd := initContainer.Command[2]
	if !strings.Contains(cmd, "keytool") {
		t.Error("Java init container should contain keytool command")
	}
	if !strings.Contains(cmd, "truststore.jks") {
		t.Error("Java init container should reference truststore.jks")
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

	// Volume mount check
	foundMount := false
	for _, m := range sidecar.VolumeMounts {
		if m.Name == "kloak-envoy-config-vol" && m.MountPath == "/etc/envoy" {
			foundMount = true
			break
		}
	}
	if !foundMount {
		t.Error("Sidecar missing envoy config volume mount")
	}
}

func TestMountCAVolume(t *testing.T) {
	h := &Handler{}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "myapp:latest"},
			},
		},
	}

	h.mountCAVolume(pod)

	// Check env vars: SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, JAVA_TOOL_OPTIONS
	if len(pod.Spec.Containers[0].Env) != 3 {
		t.Fatalf("Expected 3 env vars, got %d", len(pod.Spec.Containers[0].Env))
	}

	javaEnv := pod.Spec.Containers[0].Env[2]
	if javaEnv.Name != "JAVA_TOOL_OPTIONS" {
		t.Errorf("Expected env var 'JAVA_TOOL_OPTIONS', got '%s'", javaEnv.Name)
	}
	if !strings.Contains(javaEnv.Value, "trustStore=/etc/kloak-ca/truststore.jks") {
		t.Errorf("JAVA_TOOL_OPTIONS should reference truststore.jks, got '%s'", javaEnv.Value)
	}
	if !strings.Contains(javaEnv.Value, "trustStorePassword=changeit") {
		t.Errorf("JAVA_TOOL_OPTIONS should contain trustStorePassword, got '%s'", javaEnv.Value)
	}
	if !strings.Contains(javaEnv.Value, "preferIPv4Stack=true") {
		t.Errorf("JAVA_TOOL_OPTIONS should contain preferIPv4Stack, got '%s'", javaEnv.Value)
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

func TestNeedsJavaTruststore(t *testing.T) {
	tests := []struct {
		name     string
		pod      *corev1.Pod
		expected bool
	}{
		{
			name: "annotation override: java",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationRuntime: "java",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "myapp:latest"},
					},
				},
			},
			expected: true,
		},
		{
			name: "annotation override: non-java",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationRuntime: "python",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "eclipse-temurin:21-jre-alpine"},
					},
				},
			},
			expected: false,
		},
		{
			name: "image heuristic: temurin",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "eclipse-temurin:21-jre-alpine"},
					},
				},
			},
			expected: true,
		},
		{
			name: "image heuristic: openjdk",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "openjdk:17-slim"},
					},
				},
			},
			expected: true,
		},
		{
			name: "image heuristic: corretto",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "amazoncorretto:21"},
					},
				},
			},
			expected: true,
		},
		{
			name: "image heuristic: spring-boot",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "myorg/spring-boot-app:v1"},
					},
				},
			},
			expected: true,
		},
		{
			name: "image heuristic: quarkus",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "quarkus/my-service:latest"},
					},
				},
			},
			expected: true,
		},
		{
			name: "no match: python",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "python:3.12-slim"},
					},
				},
			},
			expected: false,
		},
		{
			name: "no match: node",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "node:22-alpine"},
					},
				},
			},
			expected: false,
		},
		{
			name: "no annotations no match",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "myapp:latest"},
					},
				},
			},
			expected: false,
		},
		{
			name: "mixed containers - one java match",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "sidecar", Image: "nginx:latest"},
						{Name: "app", Image: "eclipse-temurin:21-jre-alpine"},
					},
				},
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := needsJavaTruststore(tc.pod)
			if result != tc.expected {
				t.Errorf("needsJavaTruststore() = %v, want %v", result, tc.expected)
			}
		})
	}
}
