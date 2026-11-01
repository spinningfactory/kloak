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
)

// TestEBPFFirstRequestRewrite verifies that a container's very first TLS
// write is rewritten: with NRI the container runtime waits for the
// controller to attach the container's TLS uprobes before it starts the
// container. The container sends one request, as the first thing it does,
// and exits; the request must arrive with the real secret. Without NRI the
// controller attaches a container once it sees it running, which the first
// request can precede, so the test is skipped.
func TestEBPFFirstRequestRewrite(t *testing.T) {
	const (
		secretValue = "REAL-FIRST-REQUEST-12345"
		secretName  = "first-request-secret"
		podName     = "first-request-client"
	)
	if !controllerUsesNRI(t, controllerPod(t)) {
		t.Skip("the controller does not use NRI: a container's first request can precede its attach")
	}

	echoHost := deployTLSEchoServer(t)
	createEnabledSecret(t, secretName, map[string][]byte{"api-key": []byte(secretValue)}, nil,
		map[string]string{"getkloak.io/hosts": echoHost})
	assertShadowSecret(t, secretName, map[string][]byte{"api-key": []byte(secretValue)})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: testNamespace,
			Labels:    map[string]string{"getkloak.io/enabled": "true"},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:  "send",
				Image: "curlimages/curl:latest",
				Command: []string{"/bin/sh", "-c", fmt.Sprintf(
					`exec curl --insecure --connect-timeout 10 -s -H "X-Secret: $(cat /etc/secrets/api-key)" https://%s:8443/echo`, echoHost)},
				VolumeMounts: []corev1.VolumeMount{{Name: "secret", MountPath: "/etc/secrets", ReadOnly: true}},
			}},
			Volumes: []corev1.Volume{{
				Name:         "secret",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secretName + "-kloak"}},
			}},
		},
	}
	if _, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating pod %s: %v", podName, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
	})

	logs := waitForContainerExit(t, podName, "send", 2*time.Minute)
	if !strings.Contains(logs, secretValue) {
		t.Fatalf("the container's first request did not arrive rewritten; its log:\n%s\n=== Controller logs ===\n%s",
			logs, controllerLogs())
	}
	if !controllerLogged(t, "TLS uprobes attached before the container started", testNamespace+"/"+podName, `"send"`) {
		t.Errorf("the controller did not report attaching container send of pod %s before it started", podName)
	}
}

// controllerLogged reports whether a line of the controller's log has all of
// subs.
func controllerLogged(t *testing.T, subs ...string) bool {
	t.Helper()
	logs, err := kubectl("logs", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller", "--tail=-1")
	if err != nil {
		t.Fatalf("controller logs: %v", err)
	}
	for _, line := range strings.Split(logs, "\n") {
		if containsAll(line, subs...) {
			return true
		}
	}
	return false
}

// waitForContainerExit waits for a container of a pod to terminate and
// returns its log.
func waitForContainerExit(t *testing.T, podName, container string, timeout time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		pod, err := clientset.CoreV1().Pods(testNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err == nil {
			for _, s := range pod.Status.ContainerStatuses {
				if s.Name == container && s.State.Terminated != nil {
					logs, err := kubectl("logs", "-n", testNamespace, podName, "-c", container)
					if err != nil {
						t.Fatalf("logs of container %s: %v", container, err)
					}
					return logs
				}
			}
		}
		select {
		case <-ctx.Done():
			logs, _ := kubectl("logs", "-n", testNamespace, podName, "-c", container)
			t.Fatalf("container %s of pod %s did not terminate within %v; its log:\n%s", container, podName, timeout, logs)
		case <-time.After(pollInterval):
		}
	}
}
