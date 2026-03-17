package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"

	"github.com/go-logr/logr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func newTestHandler(objs ...client.Object) *Handler {
	scheme := k8sruntime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return &Handler{
		client:  c,
		decoder: admission.NewDecoder(scheme),
		log:     logr.Discard(),
	}
}

func makeAdmissionRequest(pod *corev1.Pod, namespace string) admission.Request {
	raw, _ := json.Marshal(pod)
	return admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: namespace,
			Object:    k8sruntime.RawExtension{Raw: raw},
		},
	}
}

func TestIsEnabled(t *testing.T) {
	nsDefault := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	nsEnabled := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "enabled-ns",
			Labels: map[string]string{AnnotationEnabled: "true"},
		},
	}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "enabled-deploy", Namespace: "default",
			Labels: map[string]string{AnnotationEnabled: "true"},
		},
	}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "enabled-deploy-rs", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "enabled-deploy"}},
		},
	}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "enabled-ds", Namespace: "default",
			Annotations: map[string]string{AnnotationEnabled: "true"},
		},
	}

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "enabled-sts", Namespace: "default",
			Labels: map[string]string{AnnotationEnabled: "true"},
		},
	}

	h := newTestHandler(nsDefault, nsEnabled, deployment, rs, ds, sts)

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
		{
			name: "inheritance from statefulset",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "StatefulSet",
							Name: "enabled-sts",
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

func TestRewriteSecretVolumes(t *testing.T) {
	enabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret", Namespace: "default",
			Labels: map[string]string{AnnotationEnabled: "true"},
		},
	}
	disabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "other-secret", Namespace: "default",
		},
	}

	h := newTestHandler(enabledSecret, disabledSecret)

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

	h.rewriteSecretVolumes(context.Background(), pod, "default")

	// Verify "my-secret" rewrote to "my-secret-kloak"
	if pod.Spec.Volumes[0].Secret.SecretName != "my-secret-kloak" {
		t.Errorf("Expected my-secret-kloak, got %s", pod.Spec.Volumes[0].Secret.SecretName)
	}

	// Verify "other-secret" stayed same
	if pod.Spec.Volumes[1].Secret.SecretName != "other-secret" {
		t.Errorf("Expected other-secret, got %s", pod.Spec.Volumes[1].Secret.SecretName)
	}
}

func TestNewHandler(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	h := NewHandler(c, logr.Discard())

	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if h.client == nil {
		t.Error("client not set")
	}
}

func TestHandle_EnabledPodWithSecretVolume(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	enabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret", Namespace: "default",
			Labels: map[string]string{AnnotationEnabled: "true"},
		},
	}
	h := newTestHandler(ns, enabledSecret)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-pod",
			Namespace:   "default",
			Annotations: map[string]string{AnnotationEnabled: "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "busybox"}},
			Volumes: []corev1.Volume{
				{
					Name: "secret-vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{SecretName: "my-secret"},
					},
				},
			},
		},
	}

	req := makeAdmissionRequest(pod, "default")
	resp := h.Handle(context.Background(), req)

	if !resp.Allowed {
		t.Fatalf("expected allowed, got denied: %v", resp.Result)
	}
	if resp.Patches == nil {
		t.Fatal("expected patches for enabled pod")
	}

	// Verify patches contain the volume rewrite
	foundVolumeRewrite := false
	for _, p := range resp.Patches {
		if p.Path == "/spec/volumes/0/secret/secretName" && p.Value == "my-secret-kloak" {
			foundVolumeRewrite = true
		}
	}
	if !foundVolumeRewrite {
		patchJSON, _ := json.Marshal(resp.Patches)
		t.Errorf("expected patch to rewrite volume to my-secret-kloak, got patches: %s", patchJSON)
	}
}

func TestHandle_DisabledPodAllowed(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	h := newTestHandler(ns)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "busybox"}}},
	}

	req := makeAdmissionRequest(pod, "default")
	resp := h.Handle(context.Background(), req)

	if !resp.Allowed {
		t.Fatalf("disabled pod should be allowed, got denied: %v", resp.Result)
	}
	if resp.Patches != nil {
		t.Error("disabled pod should have no patches")
	}
}

func TestHandle_InvalidRequest(t *testing.T) {
	h := newTestHandler()

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: "default",
			Object:    k8sruntime.RawExtension{Raw: []byte("invalid json")},
		},
	}

	resp := h.Handle(context.Background(), req)

	if resp.Allowed {
		t.Error("invalid request should be denied")
	}
	if resp.Result == nil || resp.Result.Code != http.StatusBadRequest {
		t.Errorf("expected 400 status, got %v", resp.Result)
	}
}

func TestRewriteSecretVolumes_NonSecretVolumes(t *testing.T) {
	h := newTestHandler()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "config-vol",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-config"},
						},
					},
				},
				{
					Name: "empty-vol",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			},
		},
	}

	// Should not panic or error on non-secret volumes
	h.rewriteSecretVolumes(context.Background(), pod, "default")

	if pod.Spec.Volumes[0].ConfigMap.Name != "my-config" {
		t.Error("non-secret volume should be unchanged")
	}
}

func TestRewriteSecretVolumes_EmptyNamespace(t *testing.T) {
	enabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns-secret", Namespace: "default",
			Labels: map[string]string{AnnotationEnabled: "true"},
		},
	}
	h := newTestHandler(enabledSecret)

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{SecretName: "ns-secret"},
					},
				},
			},
		},
	}

	// Empty namespace should fall back to "default"
	h.rewriteSecretVolumes(context.Background(), pod, "")

	if pod.Spec.Volumes[0].Secret.SecretName != "ns-secret-kloak" {
		t.Errorf("expected ns-secret-kloak, got %s", pod.Spec.Volumes[0].Secret.SecretName)
	}
}

func TestHandle_NamespaceInheritance(t *testing.T) {
	nsEnabled := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "enabled-ns",
			Labels: map[string]string{AnnotationEnabled: "true"},
		},
	}
	h := newTestHandler(nsEnabled)

	// Pod without annotation in enabled namespace
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "inherit-pod", Namespace: "enabled-ns"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "busybox"}}},
	}

	req := makeAdmissionRequest(pod, "enabled-ns")
	resp := h.Handle(context.Background(), req)

	if !resp.Allowed {
		t.Fatalf("pod in enabled namespace should be allowed")
	}
	if resp.Patches == nil {
		t.Fatal("pod in enabled namespace should get annotation patch")
	}
}
