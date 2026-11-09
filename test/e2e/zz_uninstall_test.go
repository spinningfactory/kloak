//go:build e2e_ebpf

package e2e

// This file runs last (go test runs the files in name order): its test
// uninstalls kloak.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// uninstalledCondition is controller.UninstalledCondition.
const uninstalledCondition = "getkloak.io/Uninstalled"

// controllerNodes returns the nodes the controllers run on.
func controllerNodes(t *testing.T) []string {
	t.Helper()
	pods, err := clientset.CoreV1().Pods(kloakNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/component=controller",
	})
	if err != nil {
		t.Fatalf("listing controller pods: %v", err)
	}
	var nodes []string
	for _, p := range pods.Items {
		if p.Spec.NodeName != "" && p.DeletionTimestamp == nil {
			nodes = append(nodes, p.Spec.NodeName)
		}
	}
	if len(nodes) == 0 {
		t.Fatal("no controller pod")
	}
	return nodes
}

var pinCheckSeq int

// nodePins returns what node's bpffs holds under kloak's pin root, as a pod
// with the host's /sys/fs/bpf sees it: "" when there is no pin root.
func nodePins(t *testing.T, node string) string {
	t.Helper()
	pinCheckSeq++
	name := fmt.Sprintf("bpffs-check-%d", pinCheckSeq)
	hostToContainer := corev1.MountPropagationHostToContainer
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: kloakNamespace},
		Spec: corev1.PodSpec{
			NodeName:      node,
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:            "check",
				Image:           e2eImage("kloak-demo-python-raw-tls", "latest"),
				ImagePullPolicy: e2ePullPolicy(),
				Command:         []string{"sh", "-c", "if [ -e /host-bpf/kloak ]; then find /host-bpf/kloak; else echo NONE; fi"},
				VolumeMounts:    []corev1.VolumeMount{{Name: "bpf", MountPath: "/host-bpf", ReadOnly: true, MountPropagation: &hostToContainer}},
			}},
			Volumes: []corev1.Volume{{Name: "bpf", VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf"},
			}}},
		},
	}
	if _, err := clientset.CoreV1().Pods(kloakNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating %s: %v", name, err)
	}
	defer func() {
		_ = clientset.CoreV1().Pods(kloakNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	}()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		p, err := clientset.CoreV1().Pods(kloakNamespace).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil && (p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not complete: %v", name, err)
		}
		time.Sleep(pollInterval)
	}
	out, err := kubectl("logs", "-n", kloakNamespace, name)
	if err != nil {
		t.Fatalf("reading %s: %v: %s", name, err, out)
	}
	out = strings.TrimSpace(out)
	if out == "NONE" {
		return ""
	}
	return out
}

// watchUninstalled records the controller pods that report the teardown
// (uninstalledCondition) until stop is called, and returns them.
func watchUninstalled() (stop func() map[string]bool) {
	ctx, cancel := context.WithCancel(context.Background())
	seen := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Go(func() {
		for ctx.Err() == nil {
			pods, err := clientset.CoreV1().Pods(kloakNamespace).List(ctx, metav1.ListOptions{
				LabelSelector: "app.kubernetes.io/component=controller",
			})
			if err == nil {
				mu.Lock()
				for _, p := range pods.Items {
					for _, c := range p.Status.Conditions {
						if string(c.Type) == uninstalledCondition && c.Status == corev1.ConditionTrue {
							seen[p.Name] = true
						}
					}
				}
				mu.Unlock()
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
	return func() map[string]bool {
		cancel()
		wg.Wait()
		return seen
	}
}

// TestZZUninstallCleansUp checks that deleting the release removes the eBPF
// data plane the controllers kept attached (spinningfactory/kloak#107): the
// pre-delete hook has every controller tear it down, and without the hook
// (helm uninstall --no-hooks, a deleted namespace) the controllers tear it
// down as they stop, seeing their DaemonSet gone.
func TestZZUninstallCleansUp(t *testing.T) {
	if os.Getenv("E2E_SKIP_INSTALL") != "" {
		t.Skip("kloak was installed outside the suite")
	}
	nodes := controllerNodes(t)
	requirePins := func(t *testing.T) {
		t.Helper()
		for _, n := range nodes {
			if got := nodePins(t, n); !strings.Contains(got, "/gens/") {
				t.Fatalf("node %s has no pinned kloak pipeline: %q", n, got)
			}
		}
	}
	requireNoPins := func(t *testing.T, how string) {
		t.Helper()
		for _, n := range nodes {
			if got := nodePins(t, n); got != "" {
				t.Errorf("%s left pins on node %s:\n%s", how, n, got)
			}
		}
	}

	t.Run("hook", func(t *testing.T) {
		requirePins(t)
		stop := watchUninstalled()
		out, err := helm("uninstall", "kloak", "-n", kloakNamespace, "--wait", "--timeout", "240s")
		reported := stop()
		if err != nil {
			t.Fatalf("helm uninstall: %v: %s", err, out)
		}
		if len(reported) < len(nodes) {
			t.Errorf("%d controllers reported the teardown, want %d (one per node): %v", len(reported), len(nodes), reported)
		}
		requireNoPins(t, "an uninstall")
	})

	t.Run("no hooks", func(t *testing.T) {
		if err := installKloak(); err != nil {
			t.Fatalf("installing kloak again: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		if err := waitForDaemonSetReady(ctx, kloakNamespace, "kloak-controller"); err != nil {
			t.Fatalf("controller not ready: %v", err)
		}
		requirePins(t)
		if out, err := helm("uninstall", "kloak", "-n", kloakNamespace, "--no-hooks", "--wait", "--timeout", "240s"); err != nil {
			t.Fatalf("helm uninstall --no-hooks: %v: %s", err, out)
		}
		requireNoPins(t, "an uninstall without hooks")
	})
}
