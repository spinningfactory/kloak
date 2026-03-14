package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestShadowSecretCreation(t *testing.T) {
	data := map[string][]byte{
		"api-key": []byte("MY-SECRET-VALUE-12345"),
	}
	createEnabledSecret(t, "test-shadow-create", data, nil)
	assertShadowSecret(t, "test-shadow-create", data)
}

func TestShadowSecretMultipleKeys(t *testing.T) {
	data := map[string][]byte{
		"username": []byte("admin-user"),
		"password": []byte("super-secret-password-123"),
		"token":    []byte("tok_live_abcdefghijklmnop"),
	}
	createEnabledSecret(t, "test-shadow-multi", data, nil)
	assertShadowSecret(t, "test-shadow-multi", data)
}

func TestShadowSecretLengthMatching(t *testing.T) {
	data := map[string][]byte{
		"short":  []byte("abcde"),                                                                                                                                                                                       // 5 bytes
		"medium": []byte("this-is-a-medium-length-secret-value-here!x"),                                                                                                                                                 // 42 bytes
		"long":   []byte(strings.Repeat("x", 200)),                                                                                                                                                                      // 200 bytes
	}
	createEnabledSecret(t, "test-shadow-lengths", data, nil)
	assertShadowSecret(t, "test-shadow-lengths", data)
}

func TestShadowSecretUpdate(t *testing.T) {
	data := map[string][]byte{
		"key": []byte("original-value-here!"),
	}
	createEnabledSecret(t, "test-shadow-update", data, nil)
	assertShadowSecret(t, "test-shadow-update", data)

	// Update the secret
	secret, err := clientset.CoreV1().Secrets(testNamespace).Get(context.Background(), "test-shadow-update", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}
	secret.Data["key"] = []byte("updated-value-here!!")
	_, err = clientset.CoreV1().Secrets(testNamespace).Update(context.Background(), secret, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("failed to update secret: %v", err)
	}

	// Wait for reconciler to process
	time.Sleep(3 * time.Second)

	// Verify shadow is updated with new length
	updatedData := map[string][]byte{
		"key": []byte("updated-value-here!!"),
	}
	assertShadowSecret(t, "test-shadow-update", updatedData)
}

func TestShadowSecretDisable(t *testing.T) {
	data := map[string][]byte{
		"key": []byte("will-be-disabled-soon"),
	}
	createEnabledSecret(t, "test-shadow-disable", data, nil)
	assertShadowSecret(t, "test-shadow-disable", data)

	// Remove the enabled label
	secret, err := clientset.CoreV1().Secrets(testNamespace).Get(context.Background(), "test-shadow-disable", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}
	delete(secret.Labels, "getkloak.io/enabled")
	_, err = clientset.CoreV1().Secrets(testNamespace).Update(context.Background(), secret, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("failed to update secret: %v", err)
	}

	// Wait for shadow to be deleted
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := waitForSecretAbsent(ctx, testNamespace, "test-shadow-disable-kloak"); err != nil {
		t.Fatalf("shadow secret not deleted after disabling: %v", err)
	}
}

func TestNonEnabledSecretIgnored(t *testing.T) {
	data := map[string][]byte{
		"key": []byte("should-not-have-shadow"),
	}
	createPlainSecret(t, "test-no-shadow", data)

	// Wait a bit and verify no shadow is created
	time.Sleep(5 * time.Second)

	_, err := clientset.CoreV1().Secrets(testNamespace).Get(context.Background(), "test-no-shadow-kloak", metav1.GetOptions{})
	if err == nil {
		t.Fatal("shadow secret should NOT exist for non-enabled secret")
	}
}
