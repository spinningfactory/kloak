package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// kubectl runs a kubectl command and returns its combined output.
func kubectl(args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("kubectl %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// helm runs a helm command and returns its combined output.
func helm(args ...string) (string, error) {
	cmd := exec.Command("helm", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("helm %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// waitForSecret polls until a secret exists in the given namespace.
func waitForSecret(ctx context.Context, namespace, name string) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for secret %s/%s", namespace, name)
		default:
		}
		_, err := clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			return nil
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
		time.Sleep(pollInterval)
	}
}

// waitForSecretAbsent polls until a secret no longer exists.
func waitForSecretAbsent(ctx context.Context, namespace, name string) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for secret %s/%s to be deleted", namespace, name)
		default:
		}
		_, err := clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		time.Sleep(pollInterval)
	}
}

// waitForPodReady polls until a pod is Running with all containers ready.
func waitForPodReady(ctx context.Context, namespace, name string) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for pod %s/%s to be ready", namespace, name)
		default:
		}
		pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				time.Sleep(pollInterval)
				continue
			}
			return err
		}
		if pod.Status.Phase == corev1.PodRunning {
			allReady := true
			for _, c := range pod.Status.ContainerStatuses {
				if !c.Ready {
					allReady = false
					break
				}
			}
			if allReady && len(pod.Status.ContainerStatuses) > 0 {
				return nil
			}
		}
		// Also accept Succeeded for short-lived pods (e.g., cat and exit)
		if pod.Status.Phase == corev1.PodSucceeded {
			return nil
		}
		time.Sleep(pollInterval)
	}
}

// waitForDeploymentReady polls until a deployment has all replicas available.
func waitForDeploymentReady(ctx context.Context, namespace, name string) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for deployment %s/%s", namespace, name)
		default:
		}
		dep, err := clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				time.Sleep(pollInterval)
				continue
			}
			return err
		}
		if dep.Status.AvailableReplicas >= *dep.Spec.Replicas {
			return nil
		}
		time.Sleep(pollInterval)
	}
}

// waitForDaemonSetReady polls until a DaemonSet has all pods ready.
func waitForDaemonSetReady(ctx context.Context, namespace, name string) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for daemonset %s/%s", namespace, name)
		default:
		}
		ds, err := clientset.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				time.Sleep(pollInterval)
				continue
			}
			return err
		}
		if ds.Status.NumberReady > 0 && ds.Status.NumberReady >= ds.Status.DesiredNumberScheduled {
			return nil
		}
		time.Sleep(pollInterval)
	}
}

// createEnabledSecret creates a secret with getkloak.io/enabled=true and registers cleanup.
func createEnabledSecret(t *testing.T, name string, data map[string][]byte, extraLabels map[string]string, extraAnnotations map[string]string) {
	t.Helper()
	if err := tryCreateEnabledSecret(t, name, data, extraLabels, extraAnnotations); err != nil {
		t.Fatalf("failed to create secret %s: %v", name, err)
	}
}

// tryCreateEnabledSecret attempts to create a kloak-enabled secret and returns
// the API error (if any) instead of calling t.Fatalf. Use this to assert that
// the validating webhook rejects an invalid configuration. Cleanup is
// registered regardless of outcome so transient creations still get removed.
func tryCreateEnabledSecret(t *testing.T, name string, data map[string][]byte, extraLabels map[string]string, extraAnnotations map[string]string) error {
	t.Helper()
	labels := map[string]string{"getkloak.io/enabled": "true"}
	for k, v := range extraLabels {
		labels[k] = v
	}
	annotations := map[string]string{}
	for k, v := range extraAnnotations {
		annotations[k] = v
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   testNamespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: data,
	}
	_, err := clientset.CoreV1().Secrets(testNamespace).Create(context.Background(), secret, metav1.CreateOptions{})
	t.Cleanup(func() {
		_ = clientset.CoreV1().Secrets(testNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	})
	return err
}

// createPlainSecret creates a secret WITHOUT getkloak.io/enabled and registers cleanup.
func createPlainSecret(t *testing.T, name string, data map[string][]byte) {
	t.Helper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Data: data,
	}
	_, err := clientset.CoreV1().Secrets(testNamespace).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create secret %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Secrets(testNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	})
}

// createPodWithSecretVolume creates a pod that mounts a secret and sleeps, registers cleanup.
func createPodWithSecretVolume(t *testing.T, name string, secretNames ...string) {
	t.Helper()
	volumes := make([]corev1.Volume, len(secretNames))
	mounts := make([]corev1.VolumeMount, len(secretNames))
	for i, sn := range secretNames {
		volName := fmt.Sprintf("vol-%d", i)
		volumes[i] = corev1.Volume{
			Name: volName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: sn},
			},
		}
		mounts[i] = corev1.VolumeMount{
			Name:      volName,
			MountPath: fmt.Sprintf("/etc/secrets/%s", sn),
			ReadOnly:  true,
		}
	}

	pod := &corev1.Pod{
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
					Name:         "test",
					Image:        "busybox:latest",
					Command:      []string{"sleep", "3600"},
					VolumeMounts: mounts,
				},
			},
			Volumes: volumes,
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

// assertShadowSecret validates the shadow secret for a given original secret name.
// Returns the shadow secret data for further assertions.
func assertShadowSecret(t *testing.T, originalName string, originalData map[string][]byte) map[string][]byte {
	t.Helper()
	shadowName := originalName + "-kloak"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := waitForSecret(ctx, testNamespace, shadowName); err != nil {
		t.Fatalf("shadow secret %s not created: %v", shadowName, err)
	}

	shadow, err := clientset.CoreV1().Secrets(testNamespace).Get(context.Background(), shadowName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get shadow secret: %v", err)
	}

	// Check managed label
	if shadow.Labels["getkloak.io/managed"] != "true" {
		t.Errorf("shadow secret missing getkloak.io/managed=true label, got labels: %v", shadow.Labels)
	}

	// Check OwnerReference
	hasOwnerRef := false
	for _, ref := range shadow.OwnerReferences {
		if ref.Name == originalName {
			hasOwnerRef = true
			break
		}
	}
	if !hasOwnerRef {
		t.Errorf("shadow secret missing OwnerReference to %s", originalName)
	}

	// Check each key
	for key, originalVal := range originalData {
		shadowVal, exists := shadow.Data[key]
		if !exists {
			t.Errorf("shadow secret missing key %q", key)
			continue
		}

		// Length must match
		if len(shadowVal) != len(originalVal) {
			t.Errorf("key %q: shadow length %d != original length %d", key, len(shadowVal), len(originalVal))
		}

		// Must start with "kloak:" prefix (or "kloak" if value is shorter than the prefix)
		kloakPrefix := "kloak:"
		if len(originalVal) < len(kloakPrefix) {
			kloakPrefix = kloakPrefix[:len(originalVal)]
		}
		if !strings.HasPrefix(string(shadowVal), kloakPrefix) {
			t.Errorf("key %q: shadow value %q does not start with expected prefix %q", key, string(shadowVal), kloakPrefix)
		}
	}

	return shadow.Data
}
