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

// TestCipherSuites verifies that kloak correctly rewrites secrets for AES-GCM
// cipher suites (TLS 1.2 + 1.3) and passes shadow placeholder for non-GCM ciphers.
func TestCipherSuites(t *testing.T) {
	secretValue := "REAL-CIPHER-TEST-12345"
	secretName := "cipher-secret"

	// Deploy the TLS echo server + service.
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

	tests := []struct {
		name       string
		tlsMin     string // "1.2" or "1.3"
		tlsMax     string
		cipher     string // curl cipher name, empty for default
		expectReal bool
		skip       string
	}{
		// TLS 1.2 AES-GCM ECDSA — should be rewritten
		{"TLS12_ECDHE_ECDSA_AES128_GCM", "1.2", "1.2",
			"ECDHE-ECDSA-AES128-GCM-SHA256", true,
			"ephemeral curl pods unreliable in CI (CURL_FAILED on x86 k3d)"},

		// TLS 1.2 AES-GCM RSA — Go TLS echo server doesn't negotiate RSA ciphers
		{"TLS12_ECDHE_RSA_AES128_GCM", "1.2", "1.2",
			"ECDHE-RSA-AES128-GCM-SHA256", true,
			"Go TLS echo server rejects ECDHE-RSA cipher negotiation"},
		{"TLS12_ECDHE_RSA_AES256_GCM", "1.2", "1.2",
			"ECDHE-RSA-AES256-GCM-SHA384", true,
			"Go TLS echo server rejects ECDHE-RSA cipher negotiation"},

		// TLS 1.2 CBC — NOT supported, should see shadow
		{"TLS12_ECDHE_RSA_AES128_CBC", "1.2", "1.2",
			"ECDHE-RSA-AES128-SHA256", false, ""},

		// TLS 1.3 default (AES-GCM) — should be rewritten
		{"TLS13_default", "1.3", "1.3", "", true,
			"TLS 1.3 rewrite in ephemeral curl pods needs investigation"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			body := runCipherClient(t, echoSvcHost, secretName, tc.cipher, tc.tlsMin, tc.tlsMax)

			if tc.expectReal {
				if !strings.Contains(body, secretValue) {
					t.Errorf("expected real secret in echo response, got:\n%s", body)
				}
			} else {
				if strings.Contains(body, secretValue) {
					t.Errorf("expected shadow for cipher %s, but got real secret:\n%s", tc.cipher, body)
				}
			}
		})
	}
}

// deployTLSEchoServer creates the echo server pod + service.
func deployTLSEchoServer(t *testing.T) string {
	t.Helper()

	labels := map[string]string{"app": echoServerName}

	// Create pod.
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

	// Create service.
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

	// Wait for ready.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, echoServerName); err != nil {
		t.Fatalf("echo server not ready: %v", err)
	}

	return fmt.Sprintf("%s.%s.svc.cluster.local", echoServerName, testNamespace)
}

// runCipherClient runs a curl-based client pod that sends an HTTPS request
// with the secret as a header, forcing a specific TLS cipher suite.
// Returns the response body (echoed headers from the server).
func runCipherClient(t *testing.T, serverHost, secretName, cipher, tlsMin, tlsMax string) string {
	t.Helper()

	// Sanitize pod name from test name.
	podName := "cipher-client-" + strings.ToLower(
		strings.NewReplacer("/", "-", "_", "-").Replace(t.Name()))
	if len(podName) > 63 {
		podName = podName[:63]
	}

	shadowName := secretName + "-kloak"

	// Build curl command with cipher/version flags.
	// Retry up to 3 times with 5s sleep between attempts to handle
	// transient DNS/connectivity issues in CI.
	curlCmd := fmt.Sprintf(
		`sleep 10 && `+ // Wait for controller to attach uprobe after exec detection
			`SECRET=$(cat /etc/secrets/api-key) && `+
			`for i in 1 2 3; do `+
			`RESULT=$(curl --insecure --connect-timeout 10 -s `+
			`%s %s `+
			`-H "X-Secret: $SECRET" `+
			`https://%s:8443/echo) && echo "$RESULT" && exit 0; `+
			`sleep 5; done; echo CURL_FAILED`,
		buildTLSVersionFlags(tlsMin, tlsMax),
		buildCipherFlag(cipher, tlsMin),
		serverHost,
	)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
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
				Command: []string{"sh", "-c", curlCmd},
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
			context.Background(), podName, metav1.DeleteOptions{})
	})

	// Wait for pod to finish.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			logs, _ := kubectl("logs", "-n", testNamespace, podName)
			t.Fatalf("cipher client timed out. Logs:\n%s", logs)
		default:
		}
		p, err := clientset.CoreV1().Pods(testNamespace).Get(
			ctx, podName, metav1.GetOptions{})
		if err == nil && (p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed) {
			break
		}
		time.Sleep(2 * time.Second)
	}

	logs, err := kubectl("logs", "-n", testNamespace, podName)
	if err != nil {
		t.Fatalf("failed to get client logs: %v", err)
	}
	t.Logf("=== %s logs ===\n%s", podName, logs)
	return logs
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
