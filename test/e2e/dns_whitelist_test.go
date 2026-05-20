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
	dnsWLClientName = "dns-wl-client"
	dnsWLEchoName   = "dns-wl-echo"
	customDNSName   = "custom-dns"
)

// TestDNSWhitelist verifies that kloak's trusted DNS server whitelist blocks
// secret rewriting when DNS responses come from an untrusted server.
//
// The controller auto-discovers kube-dns and adds it to trusted_dns_servers.
// This test deploys a custom CoreDNS forwarder (different ClusterIP) and
// configures a client pod to use it. Since the custom DNS IP is NOT in the
// whitelist, its DNS responses are dropped by the BPF kretprobe, dns_ip_map
// is never populated, resolve_host fails, and host-filtered secrets are NOT
// rewritten — the shadow placeholder passes through to the echo server.
func TestDNSWhitelist(t *testing.T) {
	secretValue := "REAL-DNS-WHITELIST-12345"
	secretName := "dns-whitelist-secret"

	// Deploy a dedicated TLS echo server with a unique name to avoid
	// collisions with TestCipherSuites.
	echoSvcHost, echoSvcIP := deployDNSWLEchoServer(t)

	// Create kloak-enabled secret with host filter targeting the echo server.
	createEnabledSecret(t, secretName, map[string][]byte{
		"api-key": []byte(secretValue),
	}, nil, map[string]string{
		"getkloak.io/hosts": echoSvcHost,
	})
	assertShadowSecret(t, secretName, map[string][]byte{
		"api-key": []byte(secretValue),
	})

	// Deploy custom CoreDNS that answers authoritatively for the echo hostname.
	// It does NOT forward to kube-dns, so the ONLY DNS response in the system
	// for this hostname comes from the custom DNS IP (untrusted).
	// This is critical because the DNS kprobe is system-wide — if CoreDNS
	// forwarded to kube-dns, kube-dns's response would populate dns_ip_map
	// via CoreDNS's own udp_recvmsg (peer=kube-dns=trusted).
	customDNSIP := deployCustomDNS(t, echoSvcHost, echoSvcIP)
	t.Logf("custom DNS service IP: %s (not in trusted_dns_servers)", customDNSIP)

	// Deploy curl client configured to use the custom (untrusted) DNS server.
	clientPod := deployCipherClientWithDNS(t, secretName, customDNSIP)

	// Verify: DNS responses from the custom resolver are dropped by the BPF
	// whitelist, so resolve_host returns no hostname, the host filter check
	// fails, and the shadow placeholder passes through unrewritten.
	verifyRewriteBlocked(t, clientPod, echoSvcHost, secretValue)
}

// deployDNSWLEchoServer creates a TLS echo server with a unique name for the
// DNS whitelist test, avoiding name collisions with TestCipherSuites.
// Returns (FQDN, ClusterIP).
func deployDNSWLEchoServer(t *testing.T) (string, string) {
	t.Helper()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dnsWLEchoName,
			Namespace: testNamespace,
			Labels: map[string]string{
				"app":                 dnsWLEchoName,
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
			context.Background(), dnsWLEchoName, metav1.DeleteOptions{})
	})

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dnsWLEchoName,
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": dnsWLEchoName},
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
			context.Background(), dnsWLEchoName, metav1.DeleteOptions{})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, dnsWLEchoName); err != nil {
		t.Fatalf("echo server not ready: %v", err)
	}

	// Fetch the assigned ClusterIP for the authoritative DNS zone.
	created, err := clientset.CoreV1().Services(testNamespace).Get(
		context.Background(), dnsWLEchoName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get echo server service: %v", err)
	}
	fqdn := fmt.Sprintf("%s.%s.svc.cluster.local", dnsWLEchoName, testNamespace)
	return fqdn, created.Spec.ClusterIP
}

// deployCustomDNS creates an authoritative CoreDNS pod + ClusterIP service
// that answers queries for echoHost with echoIP. It does NOT forward to
// kube-dns, ensuring the ONLY DNS response for this hostname comes from the
// custom DNS IP (which is NOT in trusted_dns_servers).
func deployCustomDNS(t *testing.T, echoHost, echoIP string) string {
	t.Helper()

	// Authoritative Corefile: respond to the echo hostname with its ClusterIP.
	// No forward directive — never contacts kube-dns.
	corefile := fmt.Sprintf(`.:53 {
    hosts {
        %s %s
        fallthrough
    }
    log
}
`, echoIP, echoHost)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customDNSName,
			Namespace: testNamespace,
		},
		Data: map[string]string{
			"Corefile": corefile,
		},
	}
	_, err := clientset.CoreV1().ConfigMaps(testNamespace).Create(
		context.Background(), cm, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create CoreDNS ConfigMap: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().ConfigMaps(testNamespace).Delete(
			context.Background(), customDNSName, metav1.DeleteOptions{})
	})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customDNSName,
			Namespace: testNamespace,
			Labels: map[string]string{
				"app":                 customDNSName,
				"getkloak.io/enabled": "false",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "coredns",
				Image: "coredns/coredns:1.12.0",
				Args:  []string{"-conf", "/etc/coredns/Corefile"},
				Ports: []corev1.ContainerPort{
					{ContainerPort: 53, Protocol: corev1.ProtocolUDP},
					{ContainerPort: 53, Protocol: corev1.ProtocolTCP},
				},
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "config",
					MountPath: "/etc/coredns",
					ReadOnly:  true,
				}},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						TCPSocket: &corev1.TCPSocketAction{
							Port: intstr.FromInt32(53),
						},
					},
					InitialDelaySeconds: 2,
					PeriodSeconds:       2,
				},
			}},
			Volumes: []corev1.Volume{{
				Name: "config",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: customDNSName,
						},
					},
				},
			}},
		},
	}
	_, err = clientset.CoreV1().Pods(testNamespace).Create(
		context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create CoreDNS pod: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(
			context.Background(), customDNSName, metav1.DeleteOptions{})
	})

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customDNSName,
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": customDNSName},
			Ports: []corev1.ServicePort{
				{
					Name:       "dns-udp",
					Port:       53,
					TargetPort: intstr.FromInt32(53),
					Protocol:   corev1.ProtocolUDP,
				},
				{
					Name:       "dns-tcp",
					Port:       53,
					TargetPort: intstr.FromInt32(53),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
	_, err = clientset.CoreV1().Services(testNamespace).Create(
		context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create CoreDNS service: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Services(testNamespace).Delete(
			context.Background(), customDNSName, metav1.DeleteOptions{})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, customDNSName); err != nil {
		t.Fatalf("CoreDNS pod not ready: %v", err)
	}

	created, err := clientset.CoreV1().Services(testNamespace).Get(
		context.Background(), customDNSName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get CoreDNS service: %v", err)
	}
	return created.Spec.ClusterIP
}

// deployCipherClientWithDNS creates a persistent curl pod with the shadow
// secret mounted and custom DNS configuration pointing to a non-kube-dns
// resolver. The pod uses DNSPolicy=None so all DNS queries go to the
// specified nameserver instead of kube-dns.
func deployCipherClientWithDNS(t *testing.T, secretName, dnsIP string) string {
	t.Helper()

	shadowName := secretName + "-kloak"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dnsWLClientName,
			Namespace: testNamespace,
			Labels: map[string]string{
				"getkloak.io/enabled": "true",
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			DNSPolicy:     corev1.DNSNone,
			DNSConfig: &corev1.PodDNSConfig{
				Nameservers: []string{dnsIP},
				Searches: []string{
					testNamespace + ".svc.cluster.local",
					"svc.cluster.local",
					"cluster.local",
				},
			},
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
		t.Fatalf("failed to create DNS whitelist client pod: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(
			context.Background(), dnsWLClientName, metav1.DeleteOptions{})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, dnsWLClientName); err != nil {
		t.Fatalf("DNS whitelist client pod not ready: %v", err)
	}

	return dnsWLClientName
}

// verifyRewriteBlocked polls the echo server via the client pod and confirms
// that the host-filtered secret is NOT rewritten. The shadow placeholder
// should pass through because the custom DNS IP is not in trusted_dns_servers,
// so dns_ip_map is empty and resolve_host returns no hostname.
//
// To avoid false positives from timing (uprobe not yet attached), we require
// at least 3 consecutive responses confirming the block before passing.
func verifyRewriteBlocked(t *testing.T, clientPod, serverHost, secretValue string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	curlCmd := fmt.Sprintf(
		`SECRET=$(cat /etc/secrets/api-key) && `+
			`curl --insecure --connect-timeout 10 -s `+
			`-H "X-Secret: $SECRET" https://%s:8443/echo`,
		serverHost,
	)

	consecutiveBlocked := 0
	requiredConsecutive := 3

	for {
		select {
		case <-ctx.Done():
			t.Logf("=== Controller logs ===\n%s", controllerLogs())
			t.Fatalf("timed out waiting for DNS whitelist verification (got %d/%d consecutive blocked responses)",
				consecutiveBlocked, requiredConsecutive)
		default:
		}

		out, _ := kubectl("exec", "-n", testNamespace, clientPod,
			"--", "sh", "-c", curlCmd)

		if !strings.Contains(out, `"headers"`) {
			t.Logf("waiting for echo server response: %q", out)
			time.Sleep(pollInterval)
			continue
		}

		// Fail immediately if the real secret appears — whitelist is broken.
		if strings.Contains(out, secretValue) {
			t.Fatalf("FAIL: secret was rewritten via untrusted DNS — whitelist did not block.\nResponse:\n%s", out)
		}

		// Verify the shadow placeholder passed through unrewritten.
		if strings.Contains(out, "kl::") {
			consecutiveBlocked++
			t.Logf("blocked response %d/%d confirmed (placeholder visible)", consecutiveBlocked, requiredConsecutive)
			if consecutiveBlocked >= requiredConsecutive {
				t.Logf("DNS whitelist correctly blocked secret rewrite via untrusted DNS")
				return
			}
		}

		time.Sleep(pollInterval)
	}
}
