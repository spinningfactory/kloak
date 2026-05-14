//go:build e2e_ebpf

package e2e

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// assertAdmissionRejected asserts that err is a webhook admission failure and
// that its message contains the expected reason fragment.
func assertAdmissionRejected(t *testing.T, err error, wantReason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected admission rejection (reason %q), got no error", wantReason)
	}
	// The admission webhook returns a denied status; the API surfaces it as
	// either StatusInvalid or StatusForbidden depending on k8s version. We
	// just check that the message mentions kloak + the expected reason.
	msg := err.Error()
	if !strings.Contains(msg, "kloak") {
		t.Fatalf("expected error to mention 'kloak', got: %v", err)
	}
	if !strings.Contains(msg, wantReason) {
		t.Fatalf("expected error to mention %q, got: %v", wantReason, err)
	}
	// Defensive: ensure we got a structured API error, not some random failure.
	if !apierrors.IsInvalid(err) && !apierrors.IsForbidden(err) && !strings.Contains(msg, "admission webhook") {
		t.Fatalf("expected an admission error, got: %v", err)
	}
}

func TestSecretValidation_RejectsShortData(t *testing.T) {
	err := tryCreateEnabledSecret(t, "test-val-short", map[string][]byte{
		"flag": []byte("short"), // 5 bytes, below the 8-byte BPF key minimum
	}, nil, nil)
	assertAdmissionRejected(t, err, "minimum 8")
}

func TestSecretValidation_RejectsLongData(t *testing.T) {
	err := tryCreateEnabledSecret(t, "test-val-long", map[string][]byte{
		"big": make([]byte, 129), // one byte over the 128-byte BPF rewrite cap
	}, nil, nil)
	assertAdmissionRejected(t, err, "maximum 128")
}

func TestSecretValidation_RejectsEmptyData(t *testing.T) {
	err := tryCreateEnabledSecret(t, "test-val-empty", map[string][]byte{}, nil, nil)
	assertAdmissionRejected(t, err, "no data entries")
}

func TestSecretValidation_RejectsInvalidHostLabel(t *testing.T) {
	// underscores are invalid in RFC 1123 DNS names.
	err := tryCreateEnabledSecret(t, "test-val-bad-host",
		map[string][]byte{"api-key": []byte("valid-8byte-or-more")},
		nil, map[string]string{"getkloak.io/hosts": "bad_host.example.com"})
	assertAdmissionRejected(t, err, "not a valid DNS name")
}

func TestSecretValidation_RejectsBadPortLabel(t *testing.T) {
	err := tryCreateEnabledSecret(t, "test-val-bad-port",
		map[string][]byte{"api-key": []byte("valid-8byte-or-more")},
		nil, map[string]string{"getkloak.io/port": "not-a-port"})
	assertAdmissionRejected(t, err, "invalid port")
}

func TestSecretValidation_AcceptsValidSecret(t *testing.T) {
	err := tryCreateEnabledSecret(t, "test-val-happy",
		map[string][]byte{"api-key": []byte(strings.Repeat("a", 32))},
		nil, map[string]string{
			"getkloak.io/hosts": "api.example.com",
			"getkloak.io/port":  "443",
		})
	if err != nil {
		t.Fatalf("expected valid secret to be admitted, got: %v", err)
	}
}

func TestSecretValidation_AcceptsBoundaryLengths(t *testing.T) {
	// exactly the min (8) and exactly the max (128) must pass.
	err := tryCreateEnabledSecret(t, "test-val-boundary",
		map[string][]byte{
			"min": make([]byte, 8),
			"max": make([]byte, 128),
		}, nil, nil)
	if err != nil {
		t.Fatalf("expected boundary-length secret to be admitted, got: %v", err)
	}
}

// TestSecretValidation_AllowsNonEnabledSecret proves the webhook's objectSelector
// is correctly scoped: a secret without getkloak.io/enabled=true is admitted
// even with field values that would otherwise be rejected.
func TestSecretValidation_AllowsNonEnabledSecret(t *testing.T) {
	// a short value would normally fail validation, but this secret is not kloak-enabled.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-val-plain",
			Namespace: testNamespace,
		},
		Data: map[string][]byte{"flag": []byte("x")},
	}
	_, err := clientset.CoreV1().Secrets(testNamespace).Create(context.Background(), secret, metav1.CreateOptions{})
	t.Cleanup(func() {
		_ = clientset.CoreV1().Secrets(testNamespace).Delete(context.Background(), "test-val-plain", metav1.DeleteOptions{})
	})
	if err != nil {
		t.Fatalf("expected non-enabled secret to be admitted, got: %v", err)
	}
}

// TestSecretValidation_RejectsOnUpdate proves UPDATE operations are validated,
// not just CREATE — a valid secret that becomes invalid must be blocked.
func TestSecretValidation_RejectsOnUpdate(t *testing.T) {
	name := "test-val-update"
	if err := tryCreateEnabledSecret(t, name,
		map[string][]byte{"api-key": []byte("valid-initial-value")}, nil, nil); err != nil {
		t.Fatalf("create should have succeeded: %v", err)
	}

	secret, err := clientset.CoreV1().Secrets(testNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after create failed: %v", err)
	}
	secret.Data["api-key"] = []byte("x") // now too short
	_, err = clientset.CoreV1().Secrets(testNamespace).Update(context.Background(), secret, metav1.UpdateOptions{})
	assertAdmissionRejected(t, err, "minimum 8")
}
