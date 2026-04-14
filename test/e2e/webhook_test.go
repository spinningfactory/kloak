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
	createEnabledSecret(t, "test-wh-rewrite", secretData, nil)
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
	createEnabledSecret(t, "test-wh-annot", secretData, nil)
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

	createEnabledSecret(t, "test-wh-enabled", enabledData, nil)
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

func TestWebhookMountedContent(t *testing.T) {
	secretData := map[string][]byte{"api-key": []byte("REAL-SECRET-DO-NOT-LEAK")}
	createEnabledSecret(t, "test-wh-content", secretData, nil)
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
	if !strings.Contains(output, "kloak:") {
		t.Errorf("pod output should contain 'kloak:' prefix, got: %q", output)
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
