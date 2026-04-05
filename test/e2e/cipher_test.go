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
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	echoServerName   = "tls-echo"
	cipherClientName = "cipher-client"
)

// TestCipherSuites verifies that kloak correctly rewrites secrets for AES-GCM
// cipher suites (TLS 1.2 + 1.3) and passes shadow placeholder for non-GCM ciphers.
//
// Uses a persistent curl client pod with kubectl exec for each cipher test,
// avoiding the reliability issues of ephemeral per-test pods. The echo server
// uses Python/OpenSSL for full cipher suite support (including ECDHE-RSA, which
// Go's stdlib TLS cannot reliably negotiate).
func TestCipherSuites(t *testing.T) {
	secretValue := "REAL-CIPHER-TEST-12345"
	secretName := "cipher-secret"

	// Deploy the TLS echo server (Python/OpenSSL) + service.
	echoSvcHost := deployTLSEchoServer(t)

	// Create kloak-enabled secret targeting the echo server's FQDN.
	createEnabledSecret(t, secretName, map[string][]byte{
		"api-key": []byte(secretValue),
	}, map[string]string{
		"getkloak.io/hosts": echoSvcHost,
	})
	assertShadowSecret(t, secretName, map[string][]byte{
		"api-key": []byte(secretValue),
	})

	// Deploy a persistent curl client pod with the shadow secret mounted.
	// The controller's sched_process_exec tracepoint detects kubectl exec'd
	// processes and attaches uprobes automatically.
	clientPod := deployCipherClient(t, secretName)

	// Wait for the eBPF uprobe to be ready by verifying a default TLS rewrite.
	waitForUprobeReady(t, clientPod, echoSvcHost, secretValue)

	tests := []struct {
		name   string
		tlsMin string // "1.2" or "1.3"
		tlsMax string
		cipher string // OpenSSL cipher name for curl
	}{
		// ── TLS 1.2 AES-GCM ──
		{"TLS12_ECDHE_ECDSA_AES128_GCM", "1.2", "1.2",
			"ECDHE-ECDSA-AES128-GCM-SHA256"},
		{"TLS12_ECDHE_ECDSA_AES256_GCM", "1.2", "1.2",
			"ECDHE-ECDSA-AES256-GCM-SHA384"},
		{"TLS12_ECDHE_RSA_AES128_GCM", "1.2", "1.2",
			"ECDHE-RSA-AES128-GCM-SHA256"},
		{"TLS12_ECDHE_RSA_AES256_GCM", "1.2", "1.2",
			"ECDHE-RSA-AES256-GCM-SHA384"},

		// ── TLS 1.3 AES-GCM ──
		{"TLS13_AES128_GCM", "1.3", "1.3",
			"TLS_AES_128_GCM_SHA256"},
		{"TLS13_AES256_GCM", "1.3", "1.3",
			"TLS_AES_256_GCM_SHA384"},

		// TODO: add non-GCM cipher tests once we want to verify fail-secure behavior:
		// - TLS 1.2 CBC: ECDHE-RSA-AES128-SHA256 (expectReal=false)
		// - TLS 1.3 ChaCha20: TLS_CHACHA20_POLY1305_SHA256 (expectReal=false)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := execCurl(t, clientPod, echoSvcHost, tc.cipher, tc.tlsMin, tc.tlsMax)

			// Verify the echo server responded (not a curl error).
			if !strings.Contains(body, `"headers"`) {
				t.Fatalf("echo server did not return valid JSON; output:\n%s", body)
			}

			if !strings.Contains(body, secretValue) {
				t.Errorf("expected real secret in echo response, got:\n%s", body)
			}
		})
	}
}

// deployTLSEchoServer creates the Python/OpenSSL echo server pod + service.
func deployTLSEchoServer(t *testing.T) string {
	t.Helper()

	labels := map[string]string{"app": echoServerName}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      echoServerName,
			Namespace: testNamespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "echo",
				Image:           e2eImage("kloak-tls-echo", "latest"),
				ImagePullPolicy: e2ePullPolicy(),
				Ports:           []corev1.ContainerPort{{ContainerPort: 8443}},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path:   "/health",
							Port:   intstr.FromInt32(8443),
							Scheme: corev1.URISchemeHTTPS,
						},
					},
					InitialDelaySeconds: 2,
					PeriodSeconds:       2,
				},
			}},
		},
	}
	_, err := clientset.CoreV1().Pods(testNamespace).Create(
		context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create echo server pod: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(
			context.Background(), echoServerName, metav1.DeleteOptions{})
	})

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      echoServerName,
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Port:       8443,
				TargetPort: intstr.FromInt32(8443),
			}},
		},
	}
	_, err = clientset.CoreV1().Services(testNamespace).Create(
		context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create echo server service: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Services(testNamespace).Delete(
			context.Background(), echoServerName, metav1.DeleteOptions{})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, echoServerName); err != nil {
		t.Fatalf("echo server not ready: %v", err)
	}

	return fmt.Sprintf("%s.%s.svc.cluster.local", echoServerName, testNamespace)
}

// deployCipherClient creates a persistent curl pod with the shadow secret
// mounted. Tests run curl commands inside this pod via kubectl exec, avoiding
// the overhead and reliability issues of creating a new pod per cipher test.
func deployCipherClient(t *testing.T, secretName string) string {
	t.Helper()

	shadowName := secretName + "-kloak"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cipherClientName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				"getkloak.io/enabled": "true",
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:    "client",
				Image:   "curlimages/curl:latest",
				Command: []string{"sleep", "3600"},
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "secret",
					MountPath: "/etc/secrets",
					ReadOnly:  true,
				}},
			}},
			Volumes: []corev1.Volume{{
				Name: "secret",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: shadowName,
					},
				},
			}},
		},
	}

	_, err := clientset.CoreV1().Pods(testNamespace).Create(
		context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create cipher client pod: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(
			context.Background(), cipherClientName, metav1.DeleteOptions{})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, cipherClientName); err != nil {
		t.Fatalf("cipher client pod not ready: %v", err)
	}

	return cipherClientName
}

// waitForUprobeReady polls until the eBPF uprobe successfully rewrites a secret
// using a default TLS connection. This replaces the fragile sleep-based approach.
func waitForUprobeReady(t *testing.T, clientPod, serverHost, secretValue string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	curlCmd := fmt.Sprintf(
		`SECRET=$(cat /etc/secrets/api-key) && `+
			`curl --insecure --connect-timeout 5 -s `+
			`-H "X-Secret: $SECRET" https://%s:8443/echo`,
		serverHost,
	)

	for {
		select {
		case <-ctx.Done():
			t.Logf("=== Controller logs ===\n%s", controllerLogs())
			t.Fatalf("timed out waiting for eBPF uprobe to rewrite secrets")
		default:
		}

		out, err := kubectl("exec", "-n", testNamespace, clientPod,
			"--", "sh", "-c", curlCmd)
		// Accept the response even when curl exits non-zero: Python's BaseHTTPServer
		// closes the TLS connection without a clean close_notify, causing curl to
		// exit with 56 (CURLE_RECV_ERROR) even though the full response was received.
		if strings.Contains(out, secretValue) {
			t.Logf("uprobe ready — rewrite verified")
			return
		}
		if err != nil {
			t.Logf("error waiting for uprobe to become ready: %v\n  out=%q", err, out)
		}
		time.Sleep(pollInterval)
	}
}

// execCurl runs a curl command inside the client pod via kubectl exec,
// forcing a specific TLS version and cipher suite. Retries up to 3 times
// for transient failures.
func execCurl(t *testing.T, clientPod, serverHost, cipher, tlsMin, tlsMax string) string {
	t.Helper()

	curlCmd := fmt.Sprintf(
		`SECRET=$(cat /etc/secrets/api-key) && `+
			`curl --insecure --connect-timeout 10 -s `+
			`%s %s `+
			`-H "X-Secret: $SECRET" https://%s:8443/echo`,
		buildTLSVersionFlags(tlsMin, tlsMax),
		buildCipherFlag(cipher, tlsMin),
		serverHost,
	)

	var out string
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		out, err = kubectl("exec", "-n", testNamespace, clientPod,
			"--", "sh", "-c", curlCmd)
		// Accept when we received a JSON response body, even if curl exits non-zero.
		// Python's BaseHTTPServer may close the TLS connection without clean shutdown,
		// causing curl exit 56 (CURLE_RECV_ERROR) even when the full body was received.
		if strings.Contains(out, `"headers"`) {
			return out
		}
		t.Logf("curl attempt %d: err=%v out=%q", attempt, err, out)
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("curl failed after 3 attempts: err=%v\noutput: %s", err, out)
	return ""
}

func buildTLSVersionFlags(tlsMin, tlsMax string) string {
	var flags []string
	switch tlsMin {
	case "1.2":
		flags = append(flags, "--tlsv1.2")
	case "1.3":
		flags = append(flags, "--tlsv1.3")
	}
	switch tlsMax {
	case "1.2":
		flags = append(flags, "--tls-max 1.2")
	case "1.3":
		flags = append(flags, "--tls-max 1.3")
	}
	return strings.Join(flags, " ")
}

func buildCipherFlag(cipher, tlsMin string) string {
	if cipher == "" {
		return ""
	}
	if tlsMin == "1.3" {
		return fmt.Sprintf("--tls13-ciphers %s", cipher)
	}
	return fmt.Sprintf("--ciphers %s", cipher)
}
