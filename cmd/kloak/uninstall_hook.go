package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spinningfactory/kloak/pkg/controller"
	"github.com/spinningfactory/kloak/pkg/logging"
)

var uninstallHookCmd = &cobra.Command{
	Use:   "uninstall-hook",
	Short: "Have every kloak controller tear down its node's eBPF data plane (Helm pre-delete hook)",
	Long: `The controllers keep their node's eBPF data plane attached across restarts.
Before kloak is uninstalled, this annotates the controller DaemonSet with
` + controller.UninstallAnnotation + `: each controller then detaches its node's programs,
removes their pins, and reports it on its pod (` + string(controller.UninstalledCondition) + `).

It waits for the controllers that were ready when it started, up to --timeout,
then lists the nodes it could not confirm: reboot them, or run
` + "`kloak cleanup`" + ` on them. It exits 0 either way, so the uninstall goes on.`,
	Run: runUninstallHookCmd,
}

var (
	hookDaemonSet string
	hookNamespace string
	hookTimeout   time.Duration
)

func init() {
	uninstallHookCmd.Flags().StringVar(&hookDaemonSet, "daemonset", "kloak-controller", "The controller DaemonSet.")
	uninstallHookCmd.Flags().StringVar(&hookNamespace, "namespace", os.Getenv("POD_NAMESPACE"), "The DaemonSet's namespace (default: $POD_NAMESPACE).")
	uninstallHookCmd.Flags().DurationVar(&hookTimeout, "timeout", 120*time.Second, "How long to wait for the controllers to report the teardown.")
	rootCmd.AddCommand(uninstallHookCmd)
}

func runUninstallHookCmd(_ *cobra.Command, _ []string) {
	log := logging.Setup().Named("uninstall-hook")
	defer func() { _ = log.Sync() }()
	cfg, err := ctrl.GetConfig()
	if err != nil {
		log.Errorw("no Kubernetes config: the controllers were not asked to tear down their data plane", "error", err)
		return
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Errorw("creating the Kubernetes client: the controllers were not asked to tear down their data plane", "error", err)
		return
	}
	runUninstallHook(context.Background(), c, hookNamespace, hookDaemonSet, hookTimeout, 2*time.Second, os.Stdout, log)
}

// hookNode is a controller pod the hook waits for.
type hookNode struct {
	pod, node string
	confirmed bool
	gone      bool // the pod went before it reported
}

// runUninstallHook annotates the DaemonSet ns/name for uninstall and waits,
// up to timeout (polling every poll), for the controller pods that were
// ready to report the teardown. It writes the outcome per node to out.
// Errors are reported, never returned: the uninstall must go on.
func runUninstallHook(ctx context.Context, c client.Client, ns, name string, timeout, poll time.Duration, out io.Writer, log *zap.SugaredLogger) {
	ds := &appsv1.DaemonSet{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, ds); err != nil {
		if apierrors.IsNotFound(err) {
			_, _ = fmt.Fprintf(out, "no DaemonSet %s/%s: no controller to tear down\n", ns, name)
			return
		}
		log.Errorw("reading the controller DaemonSet: the controllers were not asked to tear down their data plane", "daemonset", ns+"/"+name, "error", err)
		_, _ = fmt.Fprintf(out, "the controllers were not asked to tear down their data plane: reboot the nodes, or run `kloak cleanup` on them\n")
		return
	}
	sel, err := metav1.LabelSelectorAsSelector(ds.Spec.Selector)
	if err != nil {
		log.Errorw("reading the DaemonSet's selector", "error", err)
		return
	}
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		log.Errorw("listing the controller pods", "error", err)
	}
	var waitFor []*hookNode
	var notReady []string
	for i := range pods.Items {
		p := &pods.Items[i]
		if podReady(p) && p.DeletionTimestamp == nil {
			waitFor = append(waitFor, &hookNode{pod: p.Name, node: p.Spec.NodeName})
		} else {
			notReady = append(notReady, describeNode(p.Spec.NodeName, p.Name))
		}
	}

	patch := client.MergeFrom(ds.DeepCopy())
	if ds.Annotations == nil {
		ds.Annotations = map[string]string{}
	}
	ds.Annotations[controller.UninstallAnnotation] = time.Now().UTC().Format(time.RFC3339)
	if err := c.Patch(ctx, ds, patch); err != nil {
		log.Errorw("annotating the controller DaemonSet: the controllers were not asked to tear down their data plane", "error", err)
		_, _ = fmt.Fprintf(out, "the controllers were not asked to tear down their data plane: reboot the nodes, or run `kloak cleanup` on them\n")
		return
	}
	_, _ = fmt.Fprintf(out, "asked %d controllers to tear down their node's eBPF data plane\n", len(waitFor))

	deadline := time.Now().Add(timeout)
	for {
		pending := 0
		for _, n := range waitFor {
			if n.confirmed || n.gone {
				continue
			}
			p := &corev1.Pod{}
			err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: n.pod}, p)
			switch {
			case apierrors.IsNotFound(err):
				n.gone = true
			case err == nil && podUninstalled(p):
				n.confirmed = true
			default:
				pending++
			}
		}
		if pending == 0 || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(poll):
		}
	}

	var confirmed, unconfirmed []string
	for _, n := range waitFor {
		switch {
		case n.confirmed:
			confirmed = append(confirmed, describeNode(n.node, n.pod))
		case n.gone:
			unconfirmed = append(unconfirmed, describeNode(n.node, n.pod)+" (the controller went before it reported)")
		default:
			unconfirmed = append(unconfirmed, describeNode(n.node, n.pod)+" (no report within "+timeout.String()+")")
		}
	}
	for _, n := range notReady {
		unconfirmed = append(unconfirmed, n+" (the controller was not ready)")
	}
	sort.Strings(confirmed)
	sort.Strings(unconfirmed)
	for _, n := range confirmed {
		_, _ = fmt.Fprintf(out, "torn down: %s\n", n)
	}
	for _, n := range unconfirmed {
		_, _ = fmt.Fprintf(out, "not confirmed: %s\n", n)
	}
	if len(unconfirmed) > 0 {
		_, _ = fmt.Fprintf(out, "on a node not confirmed, a controller still tears down when the release's deletion stops it; if none runs there, reboot the node or run `kloak cleanup` on it\n")
	}
}

func describeNode(node, pod string) string {
	if node == "" {
		node = "(unscheduled)"
	}
	return "node " + node + ", pod " + pod
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func podUninstalled(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == controller.UninstalledCondition {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
