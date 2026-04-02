//go:build e2e_ebpf

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestCipherSuites verifies that kloak correctly rewrites secrets for AES-GCM
// cipher suites and leaves the shadow placeholder for non-GCM ciphers.
//
// It deploys a TLS echo server in the cluster, creates a kloak-enabled secret,
// and sends requests with each cipher suite to verify the behavior.
func TestCipherSuites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Deploy TLS echo server.
	echoServerSvc := deployEchoServer(ctx, t)
	defer cleanupEchoServer(t)

	// Create a kloak-enabled secret targeting the echo server.
	secretName := "cipher-test-secret"
	secretValue := "REAL-CIPHER-TEST-SECRET-VALUE"
	createKloakSecret(ctx, t, secretName, secretValue, echoServerSvc)
	defer deleteSecret(t, secretName)

	// Wait for shadow secret to be created by kloak controller.
	waitForShadowSecret(ctx, t, secretName)

	tests := []struct {
		name        string
		cipher      string // OpenSSL cipher name
		tlsVersion  string // "1.2" or "1.3"
		expectReal  bool   // true = expect real secret, false = expect shadow
	}{
		// TLS 1.3 AES-GCM — should be rewritten
		{"TLS13_AES_128_GCM", "TLS_AES_128_GCM_SHA256", "1.3", true},
		{"TLS13_AES_256_GCM", "TLS_AES_256_GCM_SHA384", "1.3", true},

		// TLS 1.3 ChaCha20 — NOT supported by XOR+GHASH, should see shadow
		{"TLS13_CHACHA20", "TLS_CHACHA20_POLY1305_SHA256", "1.3", false},

		// TLS 1.2 AES-GCM — should be rewritten
		{"TLS12_ECDHE_RSA_AES128_GCM", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "1.2", true},
		{"TLS12_ECDHE_RSA_AES256_GCM", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "1.2", true},
		{"TLS12_ECDHE_ECDSA_AES128_GCM", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "1.2", true},

		// TLS 1.2 CBC — NOT supported, should see shadow
		{"TLS12_ECDHE_RSA_AES128_CBC", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "1.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Deploy echo server configured for this cipher suite + TLS version.
			restartEchoServerWithCipher(ctx, t, tt.cipher, tt.tlsVersion)

			// Deploy a client pod that sends a request with the secret header.
			body := sendRequestWithSecret(ctx, t, echoServerSvc, secretName, tt.cipher, tt.tlsVersion)

			// Check if the echo server received the real secret or shadow.
			if tt.expectReal {
				if !strings.Contains(body, secretValue) {
					t.Errorf("expected real secret %q in response, got: %s", secretValue, body)
				}
			} else {
				if strings.Contains(body, secretValue) {
					t.Errorf("expected shadow placeholder (not real secret) for cipher %s, but got real secret in response", tt.cipher)
				}
				if !strings.Contains(body, "kloak:") {
					t.Errorf("expected kloak: placeholder in response for non-GCM cipher %s, got: %s", tt.cipher, body)
				}
			}
		})
	}
}

// Helper functions — implementations depend on the cluster setup.
// These create/manage k8s resources for the test.

func deployEchoServer(ctx context.Context, t *testing.T) string {
	t.Helper()
	// TODO: deploy tls-echo-server pod + service in the test namespace
	// Return the service hostname (e.g., "tls-echo-server.kloak-e2e.svc")
	t.Skip("TLS echo server deployment not yet implemented")
	return ""
}

func cleanupEchoServer(t *testing.T) {
	t.Helper()
	// TODO: delete echo server pod + service
}

func restartEchoServerWithCipher(ctx context.Context, t *testing.T, cipher, tlsVersion string) {
	t.Helper()
	// TODO: restart echo server with TLS_CIPHER_SUITES=cipher and TLS_MIN/MAX_VERSION
}

func createKloakSecret(ctx context.Context, t *testing.T, name, value, host string) {
	t.Helper()
	// TODO: create a k8s secret with getkloak.io/enabled=true and getkloak.io/hosts=host
}

func deleteSecret(t *testing.T, name string) {
	t.Helper()
	// TODO: delete the secret
}

func waitForShadowSecret(ctx context.Context, t *testing.T, name string) {
	t.Helper()
	// TODO: wait for kloak controller to create <name>-kloak shadow secret
}

func sendRequestWithSecret(ctx context.Context, t *testing.T, serverHost, secretName, cipher, tlsVersion string) string {
	t.Helper()
	// TODO: send HTTPS request from a client pod with the secret mounted as a header,
	// forcing the specified cipher suite. Return the response body (echoed headers).
	//
	// For testing from the test runner directly (if it has network access to the cluster):
	_ = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				// CipherSuites and Min/MaxVersion would be set per test case
			},
		},
	}
	_ = io.ReadAll
	_ = fmt.Sprintf
	return ""
}
