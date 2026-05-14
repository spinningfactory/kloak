package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func newTestHandler(objs ...client.Object) *Handler {
	scheme := k8sruntime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return &Handler{
		client:  c,
		decoder: admission.NewDecoder(scheme),
		log:     zap.NewNop().Sugar(),
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
			Labels: map[string]string{LabelEnabled: "true"},
		},
	}

	h := newTestHandler(nsDefault, nsEnabled)

	tests := []struct {
		name      string
		pod       *corev1.Pod
		namespace string
		expected  bool
	}{
		{
			name:      "no labels, default ns",
			pod:       &corev1.Pod{},
			namespace: "default",
			expected:  false,
		},
		{
			name: "explicit label enabled=true",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{LabelEnabled: "true"},
				},
			},
			namespace: "default",
			expected:  true,
		},
		{
			name: "explicit label enabled=false",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{LabelEnabled: "false"},
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
					Labels: map[string]string{LabelEnabled: "false"},
				},
			},
			namespace: "enabled-ns",
			expected:  false,
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
			Labels: map[string]string{LabelEnabled: "true"},
		},
	}
	shadowSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret-kloak", Namespace: "default",
			Labels: map[string]string{"getkloak.io/managed": "true"},
		},
	}
	disabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "other-secret", Namespace: "default",
		},
	}

	h := newTestHandler(enabledSecret, shadowSecret, disabledSecret)

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

func TestRewriteSecretVolumes_MissingShadowRejects(t *testing.T) {
	enabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret", Namespace: "default",
			Labels: map[string]string{LabelEnabled: "true"},
		},
	}
	// No shadow secret created

	h := newTestHandler(enabledSecret)

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{SecretName: "my-secret"},
					},
				},
			},
		},
	}

	err := h.rewriteSecretVolumes(context.Background(), pod, "default")
	if err == nil {
		t.Fatal("expected error when shadow secret is missing, got nil")
	}
	if !strings.Contains(err.Error(), "shadow secret") {
		t.Errorf("expected error about shadow secret, got: %v", err)
	}
}

func TestNewHandler(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	h := NewHandler(c, zap.NewNop().Sugar())

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
			Labels: map[string]string{LabelEnabled: "true"},
		},
	}
	shadowSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret-kloak", Namespace: "default",
			Labels: map[string]string{"getkloak.io/managed": "true"},
		},
	}
	h := newTestHandler(ns, enabledSecret, shadowSecret)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    map[string]string{LabelEnabled: "true"},
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

func TestHandle_MissingShadowDenied(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	enabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret", Namespace: "default",
			Labels: map[string]string{LabelEnabled: "true"},
		},
	}
	// No shadow secret
	h := newTestHandler(ns, enabledSecret)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    map[string]string{LabelEnabled: "true"},
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

	if resp.Allowed {
		t.Fatal("expected denied when shadow secret is missing")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "shadow secret") {
		t.Errorf("expected denial message about shadow secret, got: %v", resp.Result)
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

	err := h.rewriteSecretVolumes(context.Background(), pod, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pod.Spec.Volumes[0].ConfigMap.Name != "my-config" {
		t.Error("non-secret volume should be unchanged")
	}
}

func TestRewriteSecretVolumes_EmptyNamespace(t *testing.T) {
	enabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns-secret", Namespace: "default",
			Labels: map[string]string{LabelEnabled: "true"},
		},
	}
	shadowSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns-secret-kloak", Namespace: "default",
			Labels: map[string]string{"getkloak.io/managed": "true"},
		},
	}
	h := newTestHandler(enabledSecret, shadowSecret)

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
	err := h.rewriteSecretVolumes(context.Background(), pod, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pod.Spec.Volumes[0].Secret.SecretName != "ns-secret-kloak" {
		t.Errorf("expected ns-secret-kloak, got %s", pod.Spec.Volumes[0].Secret.SecretName)
	}
}

func TestHandle_NamespaceInheritance(t *testing.T) {
	nsEnabled := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "enabled-ns",
			Labels: map[string]string{LabelEnabled: "true"},
		},
	}
	h := newTestHandler(nsEnabled)

	// Pod without label in enabled namespace
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

// ─── env / envFrom rewriting (issue #96) ───────────────────────────────

// enabledAndShadow returns two Secret fixtures: the enabled "original" and
// the controller-managed shadow. Used by the env-rewrite tests below.
func enabledAndShadow(name, ns string) (*corev1.Secret, *corev1.Secret) {
	return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
				Labels:    map[string]string{LabelEnabled: "true"},
			},
		}, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name + "-kloak",
				Namespace: ns,
				Labels:    map[string]string{"getkloak.io/managed": "true"},
			},
		}
}

// podWithEnvSecretKeyRef returns a Pod with one container that pulls a
// single env var from `secretName` via secretKeyRef.
func podWithEnvSecretKeyRef(secretName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "env-pod",
			Namespace: "default",
			Labels:    map[string]string{LabelEnabled: "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "busybox",
				Env: []corev1.EnvVar{{
					Name: "API_KEY",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
							Key:                  "api-key",
						},
					},
				}},
			}},
		},
	}
}

func TestRewriteEnvSecretKeyRef_Enabled(t *testing.T) {
	secret, shadow := enabledAndShadow("my-secret", "default")
	h := newTestHandler(secret, shadow)

	pod := podWithEnvSecretKeyRef("my-secret")
	if err := h.rewriteSecretEnvVars(context.Background(), pod, "default"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := pod.Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.Name
	if got != "my-secret-kloak" {
		t.Errorf("expected secretKeyRef.Name=my-secret-kloak, got %q", got)
	}
}

func TestRewriteEnvSecretKeyRef_NotEnabled(t *testing.T) {
	// Secret exists but lacks the kloak-enabled label → reference must
	// be left alone, even if a name-kloak shadow happens to exist.
	plain := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"},
	}
	h := newTestHandler(plain)

	pod := podWithEnvSecretKeyRef("my-secret")
	if err := h.rewriteSecretEnvVars(context.Background(), pod, "default"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := pod.Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.Name
	if got != "my-secret" {
		t.Errorf("non-enabled secret should not be rewritten, got %q", got)
	}
}

func TestRewriteEnvSecretKeyRef_MissingShadow_Denied(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	enabled := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret", Namespace: "default",
			Labels: map[string]string{LabelEnabled: "true"},
		},
	}
	// No shadow secret in the cluster.
	h := newTestHandler(ns, enabled)

	pod := podWithEnvSecretKeyRef("my-secret")
	req := makeAdmissionRequest(pod, "default")
	resp := h.Handle(context.Background(), req)

	if resp.Allowed {
		t.Fatal("expected denial when shadow is missing for env secretKeyRef")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "shadow secret") {
		t.Errorf("expected denial message about shadow secret, got: %v", resp.Result)
	}
}

func TestRewriteEnvSecretKeyRef_OptionalMissing(t *testing.T) {
	// Optional=true + secret doesn't exist → leave reference alone,
	// matching Kubernetes' own permissive semantics for optional refs.
	h := newTestHandler() // no secrets in cluster

	pod := podWithEnvSecretKeyRef("does-not-exist")
	optional := true
	pod.Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.Optional = &optional

	if err := h.rewriteSecretEnvVars(context.Background(), pod, "default"); err != nil {
		t.Fatalf("optional+missing should not produce an error, got: %v", err)
	}
	got := pod.Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.Name
	if got != "does-not-exist" {
		t.Errorf("optional+missing should leave name alone, got %q", got)
	}
}

func TestRewriteEnvFrom_Enabled(t *testing.T) {
	secret, shadow := enabledAndShadow("env-bundle", "default")
	h := newTestHandler(secret, shadow)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "busybox",
				EnvFrom: []corev1.EnvFromSource{{
					SecretRef: &corev1.SecretEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "env-bundle"},
					},
				}},
			}},
		},
	}
	if err := h.rewriteSecretEnvVars(context.Background(), pod, "default"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := pod.Spec.Containers[0].EnvFrom[0].SecretRef.Name
	if got != "env-bundle-kloak" {
		t.Errorf("expected envFrom.SecretRef.Name=env-bundle-kloak, got %q", got)
	}
}

func TestRewriteEnvFrom_NotEnabled(t *testing.T) {
	plain := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "env-bundle", Namespace: "default"},
	}
	h := newTestHandler(plain)

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				EnvFrom: []corev1.EnvFromSource{{
					SecretRef: &corev1.SecretEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "env-bundle"},
					},
				}},
			}},
		},
	}
	if err := h.rewriteSecretEnvVars(context.Background(), pod, "default"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := pod.Spec.Containers[0].EnvFrom[0].SecretRef.Name
	if got != "env-bundle" {
		t.Errorf("non-enabled envFrom should not be rewritten, got %q", got)
	}
}

func TestRewriteContainerEnv_InitContainer(t *testing.T) {
	// initContainers must be iterated the same way as containers. Cover
	// both env-paths (secretKeyRef + envFrom) from an initContainer in
	// one shot.
	keyRefSecret, keyRefShadow := enabledAndShadow("init-key", "default")
	fromSecret, fromShadow := enabledAndShadow("init-bundle", "default")
	h := newTestHandler(keyRefSecret, keyRefShadow, fromSecret, fromShadow)

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "init",
				Image: "busybox",
				Env: []corev1.EnvVar{{
					Name: "TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "init-key"},
							Key:                  "token",
						},
					},
				}},
				EnvFrom: []corev1.EnvFromSource{{
					SecretRef: &corev1.SecretEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "init-bundle"},
					},
				}},
			}},
			// One regular container that touches no kloak-enabled secrets.
			// Its presence guards against the loop accidentally only
			// running over Spec.Containers OR Spec.InitContainers but
			// not both.
			Containers: []corev1.Container{{Name: "app", Image: "busybox"}},
		},
	}
	if err := h.rewriteSecretEnvVars(context.Background(), pod, "default"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := pod.Spec.InitContainers[0].Env[0].ValueFrom.SecretKeyRef.Name; got != "init-key-kloak" {
		t.Errorf("initContainer Env: expected init-key-kloak, got %q", got)
	}
	if got := pod.Spec.InitContainers[0].EnvFrom[0].SecretRef.Name; got != "init-bundle-kloak" {
		t.Errorf("initContainer EnvFrom: expected init-bundle-kloak, got %q", got)
	}
}

func TestRewriteContainerEnv_EphemeralContainer(t *testing.T) {
	// EphemeralContainers carry Env/EnvFrom under the embedded
	// EphemeralContainerCommon, not directly on a *corev1.Container.
	// The rewrite loop must walk that slice too — defensive coverage
	// for pods that pre-declare ephemerals at create time (the only
	// path that triggers kloak's CREATE-scoped webhook). Both
	// env-paths (secretKeyRef + envFrom) are exercised here so a
	// regression in either is caught.
	keyRefSecret, keyRefShadow := enabledAndShadow("ec-key", "default")
	fromSecret, fromShadow := enabledAndShadow("ec-bundle", "default")
	h := newTestHandler(keyRefSecret, keyRefShadow, fromSecret, fromShadow)

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "busybox"}},
			EphemeralContainers: []corev1.EphemeralContainer{{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:  "debug",
					Image: "busybox",
					Env: []corev1.EnvVar{{
						Name: "DEBUG_TOKEN",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "ec-key"},
								Key:                  "token",
							},
						},
					}},
					EnvFrom: []corev1.EnvFromSource{{
						SecretRef: &corev1.SecretEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "ec-bundle"},
						},
					}},
				},
			}},
		},
	}
	if err := h.rewriteSecretEnvVars(context.Background(), pod, "default"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := pod.Spec.EphemeralContainers[0].Env[0].ValueFrom.SecretKeyRef.Name; got != "ec-key-kloak" {
		t.Errorf("ephemeralContainer Env: expected ec-key-kloak, got %q", got)
	}
	if got := pod.Spec.EphemeralContainers[0].EnvFrom[0].SecretRef.Name; got != "ec-bundle-kloak" {
		t.Errorf("ephemeralContainer EnvFrom: expected ec-bundle-kloak, got %q", got)
	}
}

func TestRewriteContainerEnv_MultipleRefsSameSecret(t *testing.T) {
	// Two env vars sourced from the same secret → both rewritten in
	// one pass. Verifies the inner loop doesn't bail after the first
	// rewrite or short-circuit on duplicate names.
	secret, shadow := enabledAndShadow("dual", "default")
	h := newTestHandler(secret, shadow)

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "busybox",
				Env: []corev1.EnvVar{
					{
						Name: "K1",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "dual"},
								Key:                  "k1",
							},
						},
					},
					{
						Name: "K2",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "dual"},
								Key:                  "k2",
							},
						},
					},
				},
			}},
		},
	}
	if err := h.rewriteSecretEnvVars(context.Background(), pod, "default"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, ev := range pod.Spec.Containers[0].Env {
		if ev.ValueFrom.SecretKeyRef.Name != "dual-kloak" {
			t.Errorf("env[%d]=%q: expected dual-kloak, got %q",
				i, ev.Name, ev.ValueFrom.SecretKeyRef.Name)
		}
	}
}
