//go:build e2e_ebpf

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
	createEnabledSecret(t, "test-shadow-create", data, nil, nil)
	assertShadowSecret(t, "test-shadow-create", data)
}

func TestShadowSecretMultipleKeys(t *testing.T) {
	// "admin-User" (57 bits) sits at the lower edge of the kl::-prefix
	// feasibility window for length 10. The earlier "admin-user" (56
	// bits) was 1 bit below the floor — see TestSecretValidation_*
	// for the admission-time rejection of out-of-window densities.
	data := map[string][]byte{
		"username": []byte("admin-User"),
		"password": []byte("super-secret-password-123"),
		"token":    []byte("tok_live_abcdefghijklmnop"),
	}
	createEnabledSecret(t, "test-shadow-multi", data, nil, nil)
	assertShadowSecret(t, "test-shadow-multi", data)
}

func TestShadowSecretLengthMatching(t *testing.T) {
	// Values span the supported BPF range: min key size (8) to max rewrite (128).
	// Anything outside [8, 128] is rejected by the validating webhook — see
	// TestSecretValidation_RejectsShortData / TestSecretValidation_RejectsLongData.
	//
	// All three values are picked so their HPACK Huffman bit count sits
	// inside the kl::-prefix feasibility window at their length —
	// pathological all-density boundaries (e.g. "abcdefgh", "x"×128)
	// are rejected by admission and covered by TestSecretValidation_*
	// instead of this happy-path length-matching test.
	data := map[string][]byte{
		"short":  []byte("PASS1234"),
		"medium": []byte("this-is-a-medium-length-secret-value-here!x"),
		"long":   []byte(strings.Repeat("Test1234", 16)),
	}
	createEnabledSecret(t, "test-shadow-lengths", data, nil, nil)
	assertShadowSecret(t, "test-shadow-lengths", data)
}

func TestShadowSecretUpdate(t *testing.T) {
	data := map[string][]byte{
		"key": []byte("original-value-here!"),
	}
	createEnabledSecret(t, "test-shadow-update", data, nil, nil)
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

	// Verify shadow is updated with new length (assertShadowSecret polls until ready)
	updatedData := map[string][]byte{
		"key": []byte("updated-value-here!!"),
	}
	assertShadowSecret(t, "test-shadow-update", updatedData)
}

func TestShadowSecretDisable(t *testing.T) {
	data := map[string][]byte{
		"key": []byte("will-be-disabled-soon"),
	}
	createEnabledSecret(t, "test-shadow-disable", data, nil, nil)
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

	// Poll briefly and verify no shadow is created.
	// Use a short timeout — if the shadow doesn't appear in 10s, it won't.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := waitForSecret(ctx, testNamespace, "test-no-shadow-kloak")
	if err == nil {
		t.Fatal("shadow secret should NOT exist for non-enabled secret")
	}
	// Expected: timeout (no shadow created) — that's the passing case
}
