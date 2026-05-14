//go:build e2e_ebpf

package e2e

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSecretDeletionCascade(t *testing.T) {
	data := map[string][]byte{"key": []byte("cascade-delete-test-val")}
	createEnabledSecret(t, "test-cascade", data, nil, nil)
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
	createEnabledSecret(t, "test-pod-del", data, nil, nil)
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

	// Poll until controller has processed the deletion and is still healthy
	healthCtx, healthCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer healthCancel()
	for {
		select {
		case <-healthCtx.Done():
			t.Fatal("timed out waiting for controller to remain healthy after pod deletion")
		default:
		}
		out, err := kubectl("get", "pods", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller", "-o", "jsonpath={.items[0].status.phase}")
		if err == nil && out == "Running" {
			break
		}
		time.Sleep(pollInterval)
	}
}
