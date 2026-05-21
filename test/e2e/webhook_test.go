//go:build e2e_ebpf

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWebhookVolumeRewrite(t *testing.T) {
	secretData := map[string][]byte{"api-key": []byte("webhook-test-secret-val")}
	createEnabledSecret(t, "test-wh-rewrite", secretData, nil, nil)
	assertShadowSecret(t, "test-wh-rewrite", secretData)

	createPodWithSecretVolume(t, "test-wh-rewrite-pod", "test-wh-rewrite")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Wait for the pod to exist (may not be Running yet due to image pull)
	if err := waitForPodPhase(ctx, testNamespace, "test-wh-rewrite-pod"); err != nil {
		t.Fatalf("pod not created: %v", err)
	}

	// Fetch pod and verify volume was rewritten
	pod, err := clientset.CoreV1().Pods(testNamespace).Get(context.Background(), "test-wh-rewrite-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}

	for _, vol := range pod.Spec.Volumes {
		if vol.Secret != nil && vol.Secret.SecretName == "test-wh-rewrite" {
			t.Errorf("volume still references original secret 'test-wh-rewrite', expected 'test-wh-rewrite-kloak'")
		}
		if vol.Secret != nil && vol.Secret.SecretName == "test-wh-rewrite-kloak" {
			return // success
		}
	}
	t.Error("no volume found referencing shadow secret 'test-wh-rewrite-kloak'")
}

func TestWebhookAnnotationInjection(t *testing.T) {
	secretData := map[string][]byte{"key": []byte("annotation-inject-val!")}
	createEnabledSecret(t, "test-wh-annot", secretData, nil, nil)
	assertShadowSecret(t, "test-wh-annot", secretData)

	// Create pod WITHOUT the label — namespace label should trigger webhook
	name := "test-wh-annot-pod"
	createPodWithoutLabel(t, name, "test-wh-annot")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodPhase(ctx, testNamespace, name); err != nil {
		t.Fatalf("pod not created: %v", err)
	}

	pod, err := clientset.CoreV1().Pods(testNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}

	// Webhook should have injected the annotation
	if pod.Annotations["getkloak.io/enabled"] != "true" {
		t.Errorf("expected annotation getkloak.io/enabled=true, got annotations: %v", pod.Annotations)
	}

	// Volume should be rewritten
	for _, vol := range pod.Spec.Volumes {
		if vol.Secret != nil && vol.Secret.SecretName == "test-wh-annot-kloak" {
			return
		}
	}
	t.Error("volume was not rewritten to shadow secret")
}

func TestWebhookNonEnabledSecretUntouched(t *testing.T) {
	enabledData := map[string][]byte{"key": []byte("enabled-secret-value!")}
	plainData := map[string][]byte{"key": []byte("plain-secret-value!!")}

	createEnabledSecret(t, "test-wh-enabled", enabledData, nil, nil)
	createPlainSecret(t, "test-wh-plain", plainData)
	assertShadowSecret(t, "test-wh-enabled", enabledData)

	// Create pod referencing both secrets
	createPodWithSecretVolume(t, "test-wh-mixed-pod", "test-wh-enabled", "test-wh-plain")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodPhase(ctx, testNamespace, "test-wh-mixed-pod"); err != nil {
		t.Fatalf("pod not created: %v", err)
	}

	pod, err := clientset.CoreV1().Pods(testNamespace).Get(context.Background(), "test-wh-mixed-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}

	foundEnabledRewrite := false
	plainUntouched := false
	for _, vol := range pod.Spec.Volumes {
		if vol.Secret == nil {
			continue
		}
		if vol.Secret.SecretName == "test-wh-enabled-kloak" {
			foundEnabledRewrite = true
		}
		if vol.Secret.SecretName == "test-wh-plain" {
			plainUntouched = true
		}
	}

	if !foundEnabledRewrite {
		t.Error("enabled secret volume was not rewritten to shadow")
	}
	if !plainUntouched {
		t.Error("plain (non-enabled) secret volume should not be rewritten")
	}
}

func TestWebhookEnvVarRewrite(t *testing.T) {
	// secretKeyRef path: the webhook should rewrite
	// `env[].valueFrom.secretKeyRef.name` to point at the shadow,
	// same fail-closed posture as the volume path. This is the
	// Datadog-style injection model that issue #96 covers.
	secretData := map[string][]byte{"api-key": []byte("envvar-test-secret-val")}
	createEnabledSecret(t, "test-wh-env", secretData, nil, nil)
	assertShadowSecret(t, "test-wh-env", secretData)

	createPodWithSecretEnvVar(t, "test-wh-env-pod", "test-wh-env", "api-key")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodPhase(ctx, testNamespace, "test-wh-env-pod"); err != nil {
		t.Fatalf("pod not created: %v", err)
	}

	pod, err := clientset.CoreV1().Pods(testNamespace).Get(context.Background(), "test-wh-env-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}

	// Verify the secretKeyRef was rewritten to the shadow name.
	var foundRewrite bool
	for _, c := range pod.Spec.Containers {
		for _, ev := range c.Env {
			if ev.ValueFrom == nil || ev.ValueFrom.SecretKeyRef == nil {
				continue
			}
			name := ev.ValueFrom.SecretKeyRef.Name
			if name == "test-wh-env" {
				t.Errorf("env %q still references original secret 'test-wh-env', expected 'test-wh-env-kloak'", ev.Name)
			}
			if name == "test-wh-env-kloak" {
				foundRewrite = true
			}
		}
	}
	if !foundRewrite {
		t.Error("no env var found referencing shadow secret 'test-wh-env-kloak'")
	}
}

func TestWebhookEnvFromRewrite(t *testing.T) {
	// envFrom path: every key from the secret becomes an env var.
	// Same rewrite semantics — the SecretRef.Name swaps to the shadow.
	secretData := map[string][]byte{
		"api-key":   []byte("envfrom-test-secret-val"),
		"other-key": []byte("envfrom-extra-value"),
	}
	createEnabledSecret(t, "test-wh-envfrom", secretData, nil, nil)
	assertShadowSecret(t, "test-wh-envfrom", secretData)

	createPodWithSecretEnvFrom(t, "test-wh-envfrom-pod", "test-wh-envfrom")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodPhase(ctx, testNamespace, "test-wh-envfrom-pod"); err != nil {
		t.Fatalf("pod not created: %v", err)
	}

	pod, err := clientset.CoreV1().Pods(testNamespace).Get(context.Background(), "test-wh-envfrom-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}

	var foundRewrite bool
	for _, c := range pod.Spec.Containers {
		for _, ef := range c.EnvFrom {
			if ef.SecretRef == nil {
				continue
			}
			if ef.SecretRef.Name == "test-wh-envfrom" {
				t.Error("envFrom still references original secret 'test-wh-envfrom', expected 'test-wh-envfrom-kloak'")
			}
			if ef.SecretRef.Name == "test-wh-envfrom-kloak" {
				foundRewrite = true
			}
		}
	}
	if !foundRewrite {
		t.Error("no envFrom found referencing shadow secret 'test-wh-envfrom-kloak'")
	}
}

func TestWebhookMountedContent(t *testing.T) {
	secretData := map[string][]byte{"api-key": []byte("REAL-SECRET-DO-NOT-LEAK")}
	createEnabledSecret(t, "test-wh-content", secretData, nil, nil)
	assertShadowSecret(t, "test-wh-content", secretData)

	// Create a pod that cats the mounted secret and exits
	podName := "test-wh-content-pod"
	createPodThatReadsSecret(t, podName, "test-wh-content", "api-key")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodDone(ctx, testNamespace, podName); err != nil {
		t.Fatalf("pod did not complete: %v", err)
	}

	// Read pod logs
	out, err := kubectl("logs", "-n", testNamespace, podName)
	if err != nil {
		t.Fatalf("failed to read pod logs: %v", err)
	}

	output := strings.TrimSpace(out)
	if strings.Contains(output, "REAL-SECRET-DO-NOT-LEAK") {
		t.Error("pod saw the real secret value — webhook did not rewrite the volume")
	}
	if !strings.Contains(output, "kl::") {
		t.Errorf("pod output should contain 'kl::' prefix, got: %q", output)
	}
}

// createPodWithoutLabel creates a pod without getkloak.io/enabled label.
// The namespace label should trigger the webhook instead.
func createPodWithoutLabel(t *testing.T, name, secretName string) {
	t.Helper()
	pod := createBasePod(name, secretName)
	delete(pod.Labels, "getkloak.io/enabled")
	_, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create pod %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	})
}

// createPodThatReadsSecret creates a pod that cats a secret key and exits.
func createPodThatReadsSecret(t *testing.T, name, secretName, key string) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels: map[string]string{
				"getkloak.io/enabled": "true",
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:    "reader",
					Image:   "busybox:latest",
					Command: []string{"cat", fmt.Sprintf("/etc/secrets/%s/%s", secretName, key)},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "secret-vol", MountPath: fmt.Sprintf("/etc/secrets/%s", secretName), ReadOnly: true},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "secret-vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{SecretName: secretName},
					},
				},
			},
		},
	}
	_, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create pod %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	})
}

// createPodWithSecretEnvVar creates a pod that exposes a single env var
// sourced from a secret via env[].valueFrom.secretKeyRef.
func createPodWithSecretEnvVar(t *testing.T, name, secretName, key string) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels:    map[string]string{"getkloak.io/enabled": "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   "busybox:latest",
				Command: []string{"sleep", "3600"},
				Env: []corev1.EnvVar{{
					Name: "API_KEY",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
							Key:                  key,
						},
					},
				}},
			}},
		},
	}
	if _, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create pod %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	})
}

// createPodWithSecretEnvFrom creates a pod that pulls every key from
// `secretName` via envFrom[].secretRef.
func createPodWithSecretEnvFrom(t *testing.T, name, secretName string) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels:    map[string]string{"getkloak.io/enabled": "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   "busybox:latest",
				Command: []string{"sleep", "3600"},
				EnvFrom: []corev1.EnvFromSource{{
					SecretRef: &corev1.SecretEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
					},
				}},
			}},
		},
	}
	if _, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create pod %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	})
}

// createBasePod returns a pod spec with a secret volume.
func createBasePod(name, secretName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels: map[string]string{
				"getkloak.io/enabled": "true",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "test",
					Image:   "busybox:latest",
					Command: []string{"sleep", "3600"},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "secret-vol", MountPath: "/etc/secrets/" + secretName, ReadOnly: true},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "secret-vol",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{SecretName: secretName},
					},
				},
			},
		},
	}
}

// waitForPodPhase waits until a pod exists (any phase).
func waitForPodPhase(ctx context.Context, namespace, name string) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for pod %s/%s", namespace, name)
		default:
		}
		_, err := clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			return nil
		}
		time.Sleep(pollInterval)
	}
}

// waitForPodDone waits until a pod reaches Succeeded or Failed phase.
func waitForPodDone(ctx context.Context, namespace, name string) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for pod %s/%s to complete", namespace, name)
		default:
		}
		pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			return nil
		}
		time.Sleep(pollInterval)
	}
}
