package e2e

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSecretDeletionCascade(t *testing.T) {
	data := map[string][]byte{"key": []byte("cascade-delete-test-val")}
	createEnabledSecret(t, "test-cascade", data, nil)
	assertShadowSecret(t, "test-cascade", data)

	// Delete the original secret
	err := clientset.CoreV1().Secrets(testNamespace).Delete(context.Background(), "test-cascade", metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("failed to delete original secret: %v", err)
	}

	// Shadow should be garbage-collected via OwnerReference
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := waitForSecretAbsent(ctx, testNamespace, "test-cascade-kloak"); err != nil {
		t.Fatalf("shadow secret not garbage-collected: %v", err)
	}
}

func TestPodDeletion(t *testing.T) {
	data := map[string][]byte{"key": []byte("pod-delete-test-value!")}
	createEnabledSecret(t, "test-pod-del", data, nil)
	assertShadowSecret(t, "test-pod-del", data)

	createPodWithSecretVolume(t, "test-pod-del-pod", "test-pod-del")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, "test-pod-del-pod"); err != nil {
		// Pod may not reach Ready (image pull), but at least it should exist
		t.Logf("pod not fully ready (expected in CI without busybox cached): %v", err)
	}

	// Delete the pod — should not cause controller errors
	err := clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), "test-pod-del-pod", metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("failed to delete pod: %v", err)
	}

	// Brief wait to ensure controller processes the delete
	time.Sleep(3 * time.Second)

	// Verify controller is still healthy
	out, err := kubectl("get", "pods", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller", "-o", "jsonpath={.items[0].status.phase}")
	if err != nil {
		t.Fatalf("failed to check controller pod: %v", err)
	}
	if out != "Running" {
		t.Errorf("controller pod phase is %q, expected Running", out)
	}
}
