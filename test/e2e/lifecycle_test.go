//go:build e2e_ebpf

package e2e

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// lifecycleSweepInterval is ebpf.LifecycleSweepInterval: how often the
// controller detaches what exited processes and deleted pods left.
const lifecycleSweepInterval = 30 * time.Second

// linkSettleTimeout bounds how long the controller takes to detach what
// exited processes and containers left: a lifecycle sweep, and a
// container's untrack, which follows its pod's status.
const linkSettleTimeout = 3 * lifecycleSweepInterval

// TestEBPFLinkCountStable checks that the controller's eBPF links do not
// pile up (spinningfactory/kloak#107). Each process of a kloak pod running
// a binary with TLS linked in (here node, which bundles OpenSSL) gets
// uprobes of its own, on its exec event. An exec loop in the pod (what an
// exec probe does) must not leave them behind once its processes exit, and
// a container restart must not leave the old container's. Either must also
// leave the pod every link it had: the container's libraries' uprobes, which
// the restarted container shares, and the pod's tc programs.
func TestEBPFLinkCountStable(t *testing.T) {
	const podName = "link-count"
	// The main process exits when /tmp/exit appears, to restart the
	// container (a container's PID 1 ignores signals it has no handler for).
	mainScript := `setInterval(() => { if (require("fs").existsSync("/tmp/exit")) process.exit(1) }, 200)`
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: testNamespace,
			Labels:    map[string]string{"getkloak.io/enabled": "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "app",
				Image:           e2eImage("kloak-demo-js", "latest"),
				ImagePullPolicy: e2ePullPolicy(),
				Command:         []string{"node", "-e", mainScript},
			}},
		},
	}
	if _, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating pod %s: %v", podName, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, podName); err != nil {
		t.Fatalf("pod %s not ready: %v", podName, err)
	}
	ctrl := controllerPod(t)
	// The pod's own uprobes and tc programs are attached by then (the exec
	// loop below checks that its processes get theirs).
	baseline := stableLinkCount(t, ctrl)
	t.Logf("baseline: %d links", baseline)

	t.Run("exec loop", func(t *testing.T) {
		// Each exec runs node for 4 s: its exec event attaches its uprobes
		// meanwhile.
		peak := baseline
		for i := range 6 {
			var wg sync.WaitGroup
			wg.Go(func() {
				if out, err := kubectl("exec", "-n", testNamespace, podName, "-c", "app", "--",
					"node", "-e", "setTimeout(() => {}, 4000)"); err != nil {
					t.Errorf("exec %d: %v: %s", i, err, out)
				}
			})
			time.Sleep(2500 * time.Millisecond)
			if n := linkCount(t, ctrl); n > peak {
				peak = n
			}
			wg.Wait()
		}
		t.Logf("peak during the exec loop: %d links", peak)
		if peak <= baseline {
			t.Fatalf("no uprobe was attached for the exec'd processes (peak %d, baseline %d): the test does not exercise the exec path\n=== Controller logs ===\n%s",
				peak, baseline, controllerLogs())
		}
		waitForLinkCount(t, ctrl, baseline, "after the exec loop")
	})

	t.Run("container restart", func(t *testing.T) {
		for i := range 2 {
			restarts := containerRestarts(t, podName)
			if out, err := kubectl("exec", "-n", testNamespace, podName, "-c", "app", "--", "touch", "/tmp/exit"); err != nil {
				t.Fatalf("restarting the container: %v: %s", err, out)
			}
			waitFor(t, "the container to restart", func() bool { return containerRestarts(t, podName) > restarts })
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			err := waitForPodReady(ctx, testNamespace, podName)
			cancel()
			if err != nil {
				t.Fatalf("pod %s not ready after restart %d: %v", podName, i+1, err)
			}
			waitForLinkCount(t, ctrl, baseline, fmt.Sprintf("after restart %d", i+1))
		}
	})
}

// linkCount returns how many eBPF links the controller process holds: its
// bpf_link file descriptors (uprobes, kprobes, tracepoints, TCX and cgroup
// hooks alike).
func linkCount(t *testing.T, ctrl string) int {
	t.Helper()
	// hostPID: the controller is the process whose command line starts with
	// "/kloak controller".
	script := `for p in /proc/[0-9]*; do
  case "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)" in
    "/kloak controller"*) ls -l "$p/fd" 2>/dev/null | grep -c 'anon_inode:bpf_link'; exit 0;;
  esac
done
echo none`
	out, err := kubectl("exec", "-n", kloakNamespace, ctrl, "-c", "controller", "--", "sh", "-c", script)
	if err != nil {
		t.Fatalf("counting the controller's links: %v: %s", err, out)
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("counting the controller's links: unexpected output %q", out)
	}
	return n
}

// stableLinkCount returns the controller's link count once it accounts for
// this test's pod alone: no other pod of the namespace is terminating (an
// earlier test's pod releases its links as it goes), and the count held for
// longer than a lifecycle sweep (which detaches what deleted pods left).
func stableLinkCount(t *testing.T, ctrl string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for terminatingPods(t) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("pods of %s still terminating after 3m", testNamespace)
		}
		time.Sleep(pollInterval)
	}
	window := lifecycleSweepInterval + 5*time.Second
	deadline = time.Now().Add(window + linkSettleTimeout)
	n, since := linkCount(t, ctrl), time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		if m := linkCount(t, ctrl); m != n {
			n, since = m, time.Now()
			continue
		}
		if time.Since(since) >= window {
			return n
		}
	}
	t.Fatalf("the controller's link count did not hold for %s in %s (last %d)", window, window+linkSettleTimeout, n)
	return 0
}

// terminatingPods returns how many pods of the test namespace are being
// deleted.
func terminatingPods(t *testing.T) int {
	t.Helper()
	pods, err := clientset.CoreV1().Pods(testNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("listing pods of %s: %v", testNamespace, err)
	}
	n := 0
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil {
			n++
		}
	}
	return n
}

// waitForLinkCount waits for the controller's link count to come back to
// baseline: above it, links of exited processes or containers were left
// behind; below it, links the pod still needs were detached.
func waitForLinkCount(t *testing.T, ctrl string, baseline int, when string) {
	t.Helper()
	var seen []int
	deadline := time.Now().Add(linkSettleTimeout)
	for time.Now().Before(deadline) {
		n := linkCount(t, ctrl)
		seen = append(seen, n)
		if n == baseline {
			t.Logf("%s: %d links", when, n)
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("%s: the controller's link count did not come back to the baseline (%d) in %s: %v\n=== Controller logs ===\n%s",
		when, baseline, linkSettleTimeout, seen, controllerLogs())
}

// containerRestarts returns the restart count of the pod's container.
func containerRestarts(t *testing.T, podName string) int32 {
	t.Helper()
	p, err := clientset.CoreV1().Pods(testNamespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting pod %s: %v", podName, err)
	}
	if len(p.Status.ContainerStatuses) == 0 {
		return 0
	}
	return p.Status.ContainerStatuses[0].RestartCount
}

// waitFor polls cond every pollInterval for up to a minute.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("timed out waiting for %s", what)
}
