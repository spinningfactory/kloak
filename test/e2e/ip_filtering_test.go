//go:build e2e_ebpf

package e2e

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// TestEBPFIPIpFiltering tests that IP-based filtering works correctly.
// A single TLS echo server is deployed, and two secrets are created:
// - secret-ip-allowed: getkloak.io/hosts set to the echo server's ClusterIP
// - secret-ip-blocked: getkloak.io/hosts set to a fake IP (1.2.3.4)
// When the client connects to the echo server's IP, only the allowed secret
// should be rewritten; the blocked secret's placeholder should pass through.
func TestEBPFIPFiltering(t *testing.T) {
	// Wait for stale secrets from previous tests to be cleaned up.
	gcCtx, gcCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gcCancel()
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-blocked")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed-kloak")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-blocked-kloak")

	// Deploy TLS echo server and get its ClusterIP
	echoClusterIP := deployIPFilterEchoServer(t)
	t.Logf("Echo server ClusterIP: %s", echoClusterIP)

	// The client will connect to the echo server's IP directly
	// (not via hostname, so DNS resolution doesn't happen)

	allowedData := map[string][]byte{"api-key": []byte("REAL-IP-ALLOWED-KEY-12345")}
	blockedData := map[string][]byte{"api-key": []byte("REAL-IP-BLOCKED-KEY-67890")}

	// Secret allowed: hosts matches echo server's ClusterIP
	createEnabledSecret(t, "secret-allowed", allowedData, map[string]string{
		"getkloak.io/hosts": echoClusterIP,
	})

	// Secret blocked: hosts is a fake IP that will never match
	createEnabledSecret(t, "secret-blocked", blockedData, map[string]string{
		"getkloak.io/hosts": "1.2.3.4",
	})

	assertShadowSecret(t, "secret-allowed", allowedData)
	assertShadowSecret(t, "secret-blocked", blockedData)

	// Use the existing raw TLS demo deployment
	demoManifest := filepath.Join(repoRoot, "examples", "demo-python-raw-tls", "deployment.yaml")
	if err := applyManifest(t, demoManifest); err != nil {
		t.Fatalf("failed to deploy demo-python-raw-tls: %v", err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-python-raw-tls"); err != nil {
		t.Fatalf("demo-python-raw-tls not ready: %v", err)
	}

	// The client pod connects to TARGET_HOST (set to "tls" service name by default)
	// For IP-based filtering test, we need to change it to use the ClusterIP directly
	// instead of the service name (which would cause DNS resolution).
	
	// Use kubectl to patch the deployment's TARGET_HOST environment variable
	patchData := fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name":"demo-app","env":[{"name":"TARGET_HOST","value":"%s"}]}]}}}}`, echoClusterIP)
	_, err := kubectl("patch", "deployment", "demo-python-raw-tls", "-n", testNamespace, "-p", patchData)
	if err != nil {
		t.Fatalf("failed to patch deployment to use IP: %v", err)
	}
	t.Logf("Patched demo-python-raw-tls to connect to IP: %s", echoClusterIP)

	// Restart the deployment to pick up the new environment variable
	_, _ = kubectl("rollout", "restart", "deployment", "demo-python-raw-tls", "-n", testNamespace)
	ctxRestart, cancelRestart := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelRestart()
	if err := waitForDeploymentReady(ctxRestart, testNamespace, "demo-python-raw-tls"); err != nil {
		t.Fatalf("demo-python-raw-tls restart failed: %v", err)
	}

	// Poll app logs for the allowed secret and verify blocked secret placeholder
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer pollCancel()
	var out string
	for {
		select {
		case <-pollCtx.Done():
			t.Logf("=== demo-python-raw-tls final logs ===\n%s", out)
			t.Logf("=== Controller logs ===\n%s", controllerLogs())
			t.Fatalf("timed out waiting for allowed secret in raw TLS demo logs")
		default:
		}
		out, _ = kubectl("logs", "-n", testNamespace, "-l", "app=demo-python-raw-tls", "--tail=200")
		if strings.Contains(out, "REAL-IP-ALLOWED-KEY-12345") {
			break
		}
		time.Sleep(pollInterval)
	}
	t.Logf("=== demo-python-raw-tls logs ===\n%s", out)

	// Verify the blocked secret's placeholder appears (not rewritten)
	if strings.Contains(out, "REAL-IP-BLOCKED-KEY-67890") {
		t.Errorf("blocked secret should NOT be rewritten (IP mismatch)")
	}

	// Verify blocked secret's placeholder appears in output
	// If not rewritten by eBPF, the kloak: placeholder value is sent as-is
	if !strings.Contains(out, "kloak:") {
		t.Logf("output: %s", out)
		t.Errorf("blocked secret placeholder should appear unmodified in echo output")
	}
}

// deployIPFilterEchoServer creates a dedicated TLS echo server for IP filtering tests.
// Returns the ClusterIP of the service.
func deployIPFilterEchoServer(t *testing.T) string {
	t.Helper()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ip-filter-echo",
			Namespace: testNamespace,
			Labels: map[string]string{
				"app":                 "ip-filter-echo",
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
			context.Background(), "ip-filter-echo", metav1.DeleteOptions{})
	})

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ip-filter-echo",
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "ip-filter-echo"},
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
			context.Background(), "ip-filter-echo", metav1.DeleteOptions{})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, "ip-filter-echo"); err != nil {
		t.Fatalf("echo server not ready: %v", err)
	}

	// Fetch the assigned ClusterIP
	created, err := clientset.CoreV1().Services(testNamespace).Get(
		context.Background(), "ip-filter-echo", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get echo server service: %v", err)
	}
	return created.Spec.ClusterIP
}
