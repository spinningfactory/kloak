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

// TestEBPFInitContainerRewrite verifies that the TLS writes of an init
// container are rewritten. Init containers run while their pod is still
// pending, and the controller used to attach to a pod's containers only once
// it ran, so an init container (the usual place of a `git clone` into a
// shared volume) always sent its placeholder unchanged.
//
// The init container sends its placeholder to the echo server, once a
// second for up to a minute, until it comes back rewritten, and prints the
// echoed request and the attempt it took; it fails if the placeholder never
// comes back rewritten.
func TestEBPFInitContainerRewrite(t *testing.T) {
	const (
		secretValue = "REAL-INIT-CONTAINER-12345"
		secretName  = "init-container-secret"
		podName     = "init-container-client"
	)

	echoHost := deployTLSEchoServer(t)
	createEnabledSecret(t, secretName, map[string][]byte{"api-key": []byte(secretValue)}, nil,
		map[string]string{"getkloak.io/hosts": echoHost})
	assertShadowSecret(t, secretName, map[string][]byte{"api-key": []byte(secretValue)})

	pod := initContainerClientPod(podName, secretName+"-kloak", echoHost)
	if _, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating pod %s: %v", podName, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
	})

	logs := waitForInitContainer(t, podName, "send", 3*time.Minute)
	if !strings.Contains(logs, secretValue) {
		t.Fatalf("the init container's placeholder never came back rewritten; its log:\n%s\n=== Controller logs ===\n%s",
			logs, controllerLogs())
	}
	t.Logf("init container: %s", firstLineWith(logs, "rewritten on attempt"))
}

// initContainerClientPod returns a kloak pod whose init container, "send",
// sends the placeholder mounted from shadowSecret to the echo server at
// host, as described in TestEBPFInitContainerRewrite. Its app container
// exits at once.
func initContainerClientPod(name, shadowSecret, host string) *corev1.Pod {
	script := fmt.Sprintf(`i=0
while [ $i -lt 60 ]; do
  i=$((i+1))
  out=$(curl --insecure --connect-timeout 5 -s -H "X-Secret: $(cat /etc/secrets/api-key)" https://%s:8443/echo)
  case "$out" in
    *X-Secret*kl::*) ;;
    *X-Secret*) echo "rewritten on attempt $i"; echo "$out"; exit 0 ;;
  esac
  sleep 1
done
echo "not rewritten after $i attempts; last response: $out"
exit 1`, host)
	mounts := []corev1.VolumeMount{{Name: "secret", MountPath: "/etc/secrets", ReadOnly: true}}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels:    map[string]string{"getkloak.io/enabled": "true"},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			InitContainers: []corev1.Container{{
				Name:         "send",
				Image:        "curlimages/curl:latest",
				Command:      []string{"/bin/sh", "-c", script},
				VolumeMounts: mounts,
			}},
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   "curlimages/curl:latest",
				Command: []string{"true"},
			}},
			Volumes: []corev1.Volume{{
				Name:         "secret",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: shadowSecret}},
			}},
		},
	}
}

// waitForInitContainer waits for the init container of a pod to terminate
// and returns its log.
func waitForInitContainer(t *testing.T, podName, container string, timeout time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		pod, err := clientset.CoreV1().Pods(testNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err == nil {
			for _, s := range pod.Status.InitContainerStatuses {
				if s.Name == container && s.State.Terminated != nil {
					logs, err := kubectl("logs", "-n", testNamespace, podName, "-c", container)
					if err != nil {
						t.Fatalf("logs of init container %s: %v", container, err)
					}
					return logs
				}
			}
		}
		select {
		case <-ctx.Done():
			logs, _ := kubectl("logs", "-n", testNamespace, podName, "-c", container)
			t.Fatalf("init container %s of pod %s did not terminate within %v; its log:\n%s", container, podName, timeout, logs)
		case <-time.After(pollInterval):
		}
	}
}

func firstLineWith(s, sub string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, sub) {
			return line
		}
	}
	return ""
}
