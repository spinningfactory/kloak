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
	echoServerName = "tls-echo"
)

// opensslClient defines a curl client image with a specific OpenSSL version
// for testing different H extraction chains (4-hop for 3.2+, 3-hop for 3.0-3.1).
type opensslClient struct {
	name  string // unique pod name suffix
	image string // container image with curl + specific OpenSSL
	chain string // "4-hop" or "3-hop" (for test naming)
}

// TestCipherSuites verifies that kloak correctly rewrites secrets for AES-GCM
// cipher suites (TLS 1.2 + 1.3) across multiple OpenSSL versions, covering
// both the 4-hop chain (3.2+) and 3-hop chain (3.0-3.1).
//
// Uses persistent curl client pods with kubectl exec for each cipher test,
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

	// OpenSSL client images: test both the 4-hop (3.2+) and 3-hop (3.0-3.1) chains.
	// curlimages/curl:latest → Alpine, OpenSSL 3.5.x (4-hop)
	// debian:bookworm-slim → Debian 12, OpenSSL 3.0.x (3-hop), curl installed at runtime
	clients := []opensslClient{
		{name: "cipher-client-3x", image: "curlimages/curl:latest", chain: "4hop"},
		{name: "cipher-client-30", image: "debian:bookworm-slim", chain: "3hop"},
	}

	ciphers := []struct {
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

	for _, client := range clients {
		t.Run(client.chain, func(t *testing.T) {
			clientPod := deployCipherClient(t, secretName, client)
			waitForUprobeReady(t, clientPod, echoSvcHost, secretValue)

			for _, tc := range ciphers {
				t.Run(tc.name, func(t *testing.T) {
					body := execCurl(t, clientPod, echoSvcHost, tc.cipher, tc.tlsMin, tc.tlsMax)

					if !strings.Contains(body, `"headers"`) {
						t.Fatalf("echo server did not return valid JSON; output:\n%s", body)
					}

					if !strings.Contains(body, secretValue) {
						t.Errorf("expected real secret in echo response, got:\n%s", body)
					}
				})
			}
		})
	}
}

// deployTLSEchoServer creates the Python/OpenSSL echo server pod + service.
func deployTLSEchoServer(t *testing.T) string {
	t.Helper()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      echoServerName,
			Namespace: testNamespace,
			// Explicitly opt out of kloak interception. The echo server is test
			// infrastructure — attaching tc egress to it corrupts its outbound
			// TLS records (bad record MAC on readiness probes).
			Labels: map[string]string{
				"app":                 echoServerName,
				"getkloak.io/enabled": "false",
			},
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
			Selector: map[string]string{"app": echoServerName},
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
//
// For Alpine-based images (curlimages/curl), curl is pre-installed.
// For Debian-based images, an init container installs curl + ca-certificates.
func deployCipherClient(t *testing.T, secretName string, client opensslClient) string {
	t.Helper()

	shadowName := secretName + "-kloak"

	container := corev1.Container{
		Name:    "client",
		Image:   client.image,
		Command: []string{"sleep", "3600"},
		VolumeMounts: []corev1.VolumeMount{{
			Name:      "secret",
			MountPath: "/etc/secrets",
			ReadOnly:  true,
		}},
	}

	var initContainers []corev1.Container
	// Debian images need curl installed at runtime.
	if strings.Contains(client.image, "debian") {
		container.Command = []string{"/bin/sh", "-c",
			"apt-get update -qq && apt-get install -y -qq curl ca-certificates > /dev/null 2>&1 && sleep 3600"}
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      client.name,
			Namespace: testNamespace,
			Labels: map[string]string{
				"getkloak.io/enabled": "true",
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy:  corev1.RestartPolicyNever,
			InitContainers: initContainers,
			Containers:     []corev1.Container{container},
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
		t.Fatalf("failed to create cipher client pod %s: %v", client.name, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(
			context.Background(), client.name, metav1.DeleteOptions{})
	})

	// Debian images take longer to become ready (apt-get install).
	timeout := 60 * time.Second
	if strings.Contains(client.image, "debian") {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, client.name); err != nil {
		t.Fatalf("cipher client pod %s not ready: %v", client.name, err)
	}

	// Debian images install curl at runtime via apt-get. Wait for it to
	// be available before returning, so callers don't get "curl: not found".
	if strings.Contains(client.image, "debian") {
		for {
			select {
			case <-ctx.Done():
				t.Fatalf("curl not available in %s after timeout", client.name)
			default:
			}
			out, _ := kubectl("exec", "-n", testNamespace, client.name,
				"--", "which", "curl")
			if strings.Contains(out, "curl") {
				break
			}
			time.Sleep(2 * time.Second)
		}
	}

	return client.name
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
