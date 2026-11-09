package main

import (
	"context"
	"net"
	"os"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/spinningfactory/kloak/pkg/controller"
	"github.com/spinningfactory/kloak/pkg/ebpf"
	"github.com/spinningfactory/kloak/pkg/logging"
	k8ssecrets "github.com/spinningfactory/kloak/pkg/secrets/k8s"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

var controllerCmd = &cobra.Command{
	Use:   "controller",
	Short: "Run the Kloak controller",
	Long: `Starts the Kubernetes controller that watches pods and secrets
and manages eBPF uprobe programs for in-kernel TLS secret rewriting.

The controller is responsible for:
- Watching K8s Secrets labeled getkloak.io/enabled=true and creating shadow secrets
- Attaching eBPF TLS uprobes to tracked pod processes`,
	Run: runController,
}

var (
	controllerProbeAddr string
	enableEBPF          bool
	cgroupPath          string
	trustedDNSServers   string
	egressInterface     string
	tcAttachMode        string
	secretBinding       string
	sniCheck            string
	virtualIPRange      string
	nriSocket           string
	daemonSetName       string
	nodeLockPath        string
)

// adoptReconcileTimeout bounds how long a controller that adopted the
// pinned eBPF objects waits for the pods running at its start to be
// reconciled before it detaches what none of them claimed.
const adoptReconcileTimeout = 60 * time.Second

func init() {
	controllerCmd.Flags().StringVar(&controllerProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	controllerCmd.Flags().BoolVar(&enableEBPF, "enable-ebpf", false, "Enable eBPF traffic redirection (requires Linux + CAP_BPF).")
	controllerCmd.Flags().StringVar(&cgroupPath, "cgroup-path", "/sys/fs/cgroup", "Path to cgroup v2 filesystem.")
	controllerCmd.Flags().StringVar(&trustedDNSServers, "trusted-dns-servers", "", "Comma-separated DNS server IPs trusted in addition to kube-dns's ClusterIPs and endpoint addresses, which are discovered: only their answers are rewritten for host-restricted secrets.")
	controllerCmd.Flags().StringVar(&egressInterface, "egress-interface", "auto",
		"Container interface whose host-side veth peer gets the tc patch program (tc ingress). "+
			`"auto" detects from the default route in the container netns, IPv4 or else IPv6 (works for CNI veth "eth0" AND host-mode netns with non-standard names like wlp3s0/enp0s3). `+
			`Use an explicit name (e.g., "eth0") to pin, or "none"/"lo-only" to disable external attachment. `+
			`Loopback is never patched.`)
	controllerCmd.Flags().StringVar(&tcAttachMode, "tc-attach-mode", "auto",
		`How the tc patch program is attached: "auto" uses TCX on Linux 6.6+ and falls back to a clsact qdisc + cls_bpf filter on older kernels; `+
			`"tcx" requires TCX; "clsact" always uses the classic filter.`)
	controllerCmd.Flags().StringVar(&secretBinding, "secret-binding", "enforce",
		`Which pods may redeem a secret's placeholder: only pods that reference the secret in their spec (Secret volume, env secretKeyRef, envFrom). `+
			`"enforce" refuses other pods' rewrites; "audit" allows them but logs each violation, to find such workloads before enforcing.`)
	controllerCmd.Flags().StringVar(&sniCheck, "sni-check", "enforce",
		`A secret restricted to a hostname (getkloak.io/hosts) is only rewritten on a connection whose TLS ClientHello names that host (SNI). `+
			`"enforce" refuses other rewrites; "audit" allows them but logs each violation, to find clients whose SNI differs from the annotation before enforcing.`)
	controllerCmd.Flags().StringVar(&nriSocket, "nri-socket", controller.DefaultNRISocket,
		`NRI socket of the container runtime (containerd 2.0+, CRI-O 1.30+): the runtime then waits for kloak to attach the DNS rewrite while it creates each pod sandbox, before the pod's containers start, and a container's TLS uprobes before it starts. `+
			`Without NRI (unreachable socket, or "" to disable), the rewrite is attached by polling pending pods, and a container's uprobes once the pod's status reports it running, which leaves a short window at pod start in which a lookup gets the real addresses and a connection made with them no host-restricted secret, and a TLS write sends the placeholder unchanged.`)
	controllerCmd.Flags().StringVar(&daemonSetName, "daemonset", "",
		`The controller's DaemonSet, in the namespace POD_NAMESPACE names. When set, the eBPF data plane outlives the controller: its programs and maps stay pinned under `+ebpf.DefaultBPFPinPath+` and attached across restarts, rollouts and upgrades, and the next controller adopts them, so the pods' secrets are rewritten all along. `+
			`On shutdown it is kept only while the DaemonSet stays and its pod template is annotated `+controller.PinFormatAnnotation+` (its controllers adopt the pins; the Helm chart sets it); it is torn down when the DaemonSet is being deleted, annotated `+controller.UninstallAnnotation+` (the Helm chart's pre-delete hook), or kloak's RBAC is gone, and detached otherwise. `+
			`Empty: the data plane is detached on every shutdown, and what a previous controller kept is detached at startup.`)
	controllerCmd.Flags().StringVar(&nodeLockPath, "node-lock", DefaultNodeLock,
		`File the controller locks (flock) while it runs, on a host directory: a controller waits for the previous one on the node to exit before it touches the node's eBPF objects. "" disables it.`)
	controllerCmd.Flags().StringVar(&virtualIPRange, "virtual-ip-range", ebpf.DefaultVirtualIPRange,
		`Ranges fake IPs come from. Every host a secret is restricted to (getkloak.io/hosts) gets a stable fake IP, and fake IPv6, kept in maps pinned under `+ebpf.DefaultBPFPinPath+`. `+
			`A kloak pod with a secret for the host gets the fake IP in DNS answers and its connects to it are redirected to the host's addresses; a host-restricted secret is only rewritten on a connection made to its host's fake IP. `+
			`An IPv4 range (/19 or larger) and, optionally, an IPv6 one (/115 or larger), comma-separated. `+
			`Without an IPv6 range, AAAA answers are left unchanged. `+
			`The controller refuses to start if a range overlaps a node address, pod CIDR, service CIDR or route of the node.`)
}

func runController(cmd *cobra.Command, args []string) {
	setupLog := logging.Setup().Named("setup")

	setupLog.Infow("Starting Kloak controller", "ebpf", enableEBPF, "cgroupPath", cgroupPath, "egressInterface", egressInterface, "tcAttachMode", tcAttachMode, "secretBinding", secretBinding, "sniCheck", sniCheck, "virtualIPRange", virtualIPRange, "nriSocket", nriSocket, "daemonset", daemonSetName)
	signalCtx := ctrl.SetupSignalHandler()
	namespace := os.Getenv("POD_NAMESPACE")
	persist := enableEBPF && daemonSetName != ""
	if persist && namespace == "" {
		setupLog.Warnw("--daemonset without POD_NAMESPACE: the eBPF data plane is detached on every shutdown")
		persist = false
	}

	tcMode, err := ebpf.ParseTCAttachMode(tcAttachMode)
	if err != nil {
		setupLog.Errorw("invalid --tc-attach-mode", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}
	bindingMode, err := ebpf.ParseSecretBindingMode(secretBinding)
	if err != nil {
		setupLog.Errorw("invalid --secret-binding", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}
	sniMode, err := ebpf.ParseSNICheckMode(sniCheck)
	if err != nil {
		setupLog.Errorw("invalid --sni-check", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}
	vipRanges, err := ebpf.ParseVirtualIPRanges(virtualIPRange)
	if err != nil {
		setupLog.Errorw("invalid --virtual-ip-range", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}
	hostRes := ebpf.HostResolutionConfig{VirtualIPRanges: vipRanges}

	// 30 s is well under the daemonset's 60 s terminationGracePeriodSeconds,
	// leaving headroom for our own cleanup (uprobe/link Close) and any final
	// log flush before kubelet's SIGKILL. Without this the manager defaults
	// to 30 s anyway, but pinning it documents the budget and makes it
	// obvious where to tune if shutdown ever pushes past the grace period.
	gracefulShutdown := 30 * time.Second
	// The trusted DNS reconciler only needs kube-dns: cache that, not
	// every Service and EndpointSlice of the cluster.
	byObject := map[client.Object]cache.ByObject{
		&corev1.Service{}: {Namespaces: map[string]cache.Config{controller.KubeDNSNamespace: {
			FieldSelector: fields.OneTermEqualSelector("metadata.name", controller.KubeDNSName),
		}}},
		&discoveryv1.EndpointSlice{}: {Namespaces: map[string]cache.Config{controller.KubeDNSNamespace: {
			LabelSelector: labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: controller.KubeDNSName}),
		}}},
	}
	if persist {
		// The uninstall watcher only needs the controller's own DaemonSet.
		byObject[&appsv1.DaemonSet{}] = cache.ByObject{Namespaces: map[string]cache.Config{namespace: {
			FieldSelector: fields.OneTermEqualSelector("metadata.name", daemonSetName),
		}}}
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		HealthProbeBindAddress:  controllerProbeAddr,
		GracefulShutdownTimeout: &gracefulShutdown,
		Cache:                   cache.Options{ByObject: byObject},
	})
	if err != nil {
		setupLog.Errorw("unable to start manager", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}

	// Create uprobe manager instances
	var uprobeMgr *ebpf.TLSUprobeManager
	// nodeLock holds the node lock until the eBPF data plane is shut down.
	var nodeLock *os.File

	if enableEBPF {
		// The controller runs with hostPID: /proc/1 is in the host network
		// namespace.
		checkCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = checkVirtualIPRanges(checkCtx, mgr.GetAPIReader(), hostRes.VirtualIPRanges, "/proc/1", setupLog)
		cancel()
		if err != nil {
			setupLog.Errorw("invalid --virtual-ip-range: set ranges that no address of the cluster or node uses (Helm: controller.ebpf.virtualIPRange)",
				"range", hostRes.VirtualIPRanges.String(), "error", err)
			_ = setupLog.Sync()
			os.Exit(1)
		}
		// One controller at a time on the node's eBPF objects: a new one
		// waits for the previous one to exit (it may still be keeping or
		// tearing them down).
		if nodeLockPath != "" {
			nodeLock, err = lockNode(signalCtx, nodeLockPath, setupLog)
			if err != nil {
				setupLog.Errorw("failed to take the node lock", "error", err)
				_ = setupLog.Sync()
				os.Exit(1)
			}
		}
		uprobeMgr, err = ebpf.NewTLSUprobeManager(k8ssecrets.NewSource(mgr.GetClient()).WithLog(setupLog), cgroupPath, egressInterface, &hostRes, persist, setupLog)
		if err != nil {
			setupLog.Errorw("failed to initialize eBPF uprobe manager", "error", err)
			_ = setupLog.Sync()
			os.Exit(1)
		}
		uprobeMgr.SetTCAttachMode(tcMode)
		uprobeMgr.SetSecretBindingMode(bindingMode)
		uprobeMgr.SetSNICheckMode(sniMode)
		setupLog.Infow("eBPF TLS uprobes enabled")
	} else {
		setupLog.Infow("eBPF disabled")
	}

	// Create pod reconciler
	// NODE_NAME is used to filter pods to only those on this node (DaemonSet per-node controller)
	nodeName := os.Getenv("NODE_NAME")
	if nodeName != "" {
		setupLog.Infow("Node filtering enabled", "nodeName", nodeName)
	}
	reconciler := controller.NewReconciler(
		mgr.GetClient(),
		setupLog.Named("controller").Named("Pod"),
		mgr.GetScheme(),
		uprobeMgr,
		cgroupPath,
		nodeName,
	)

	reconciler.APIReader = mgr.GetAPIReader()

	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Errorw("unable to create controller", "error", err, "controller", "Pod")
		_ = setupLog.Sync()
		os.Exit(1)
	}

	// With NRI the container runtime waits for the DNS rewrite to be
	// attached before a pod's containers start, and for a container's TLS
	// uprobes before it starts; without it, the reconciler polls pending
	// pods and attaches running containers. Added as a runnable so it starts
	// after the cache sync (PrepareSandbox and PrepareContainer read pods
	// from the cache).
	if uprobeMgr != nil && nriSocket != "" {
		plugin := &controller.NRIPlugin{
			Preparer:   reconciler,
			SocketPath: nriSocket,
			Log:        setupLog.Named("nri"),
		}
		if err := mgr.Add(manager.RunnableFunc(plugin.Run)); err != nil {
			setupLog.Errorw("unable to add the NRI plugin runnable", "error", err)
			_ = setupLog.Sync()
			os.Exit(1)
		}
	}

	// Create secret reconciler
	secretReconciler := &controller.SecretReconciler{
		Client: mgr.GetClient(),
		Log:    setupLog.Named("controller").Named("Secret"),
		Scheme: mgr.GetScheme(),
	}

	if err := secretReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Errorw("unable to create controller", "error", err, "controller", "Secret")
		os.Exit(1)
	}

	// Tear the node's data plane down when the uninstall hook asks for it.
	var uninstall *controller.UninstallWatcher
	readyCheck := healthz.Ping
	if persist && uprobeMgr != nil {
		uninstall = &controller.UninstallWatcher{
			Client:    mgr.GetClient(),
			Namespace: namespace,
			Name:      daemonSetName,
			PodName:   os.Getenv("POD_NAME"),
			Uninstall: uprobeMgr.Uninstall,
			Log:       setupLog.Named("controller").Named("Uninstall"),
		}
		if err := uninstall.SetupWithManager(mgr); err != nil {
			setupLog.Errorw("unable to create controller", "error", err, "controller", "Uninstall")
			_ = setupLog.Sync()
			os.Exit(1)
		}
		readyCheck = uninstall.ReadyCheck
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Errorw("unable to set up health check", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", readyCheck); err != nil {
		setupLog.Errorw("unable to set up ready check", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}

	// Configure trusted DNS servers for the eBPF DNS chain of trust: now,
	// before the manager starts (an empty whitelist believes every server),
	// then as kube-dns's endpoints change.
	if uprobeMgr != nil {
		dnsIPs := discoverTrustedDNSServers(mgr.GetAPIReader(), setupLog)
		if err := uprobeMgr.PopulateTrustedDNSServers(dnsIPs); err != nil {
			setupLog.Errorw("failed to populate trusted DNS servers", "error", err)
		}
		dnsReconciler := &controller.TrustedDNSReconciler{
			Client: mgr.GetClient(),
			Static: parseTrustedDNSServers(trustedDNSServers, setupLog),
			Apply:  uprobeMgr.PopulateTrustedDNSServers,
			Log:    setupLog.Named("controller").Named("TrustedDNS"),
		}
		if err := dnsReconciler.SetupWithManager(mgr); err != nil {
			setupLog.Errorw("unable to create controller", "error", err, "controller", "TrustedDNS")
			_ = setupLog.Sync()
			os.Exit(1)
		}

		// Sync secrets into the BPF maps as kloak Secrets change, and
		// every DefaultSecretResyncPeriod.
		secretSync := &controller.SecretSyncReconciler{Sync: uprobeMgr.SyncSecrets}
		if err := secretSync.SetupWithManager(mgr); err != nil {
			setupLog.Errorw("unable to create controller", "error", err, "controller", "SecretSync")
			_ = setupLog.Sync()
			os.Exit(1)
		}
	}

	// Register eBPF pollers as manager runnables so they start after the
	// informer cache is synced.
	if uprobeMgr != nil {
		if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
			return uprobeMgr.PollEvents(ctx)
		})); err != nil {
			setupLog.Errorw("unable to add eBPF event poller runnable", "error", err)
			_ = setupLog.Sync()
			os.Exit(1)
		}
		if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
			return uprobeMgr.PollExecEvents(ctx)
		})); err != nil {
			setupLog.Errorw("unable to add eBPF exec event poller runnable", "error", err)
			_ = setupLog.Sync()
			os.Exit(1)
		}
		// Detach what processes and containers that went left attached, and
		// prune the BPF maps keyed by cgroup.
		if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
			return uprobeMgr.RunLifecycleSweep(ctx, ebpf.LifecycleSweepInterval)
		})); err != nil {
			setupLog.Errorw("unable to add eBPF lifecycle sweep runnable", "error", err)
			_ = setupLog.Sync()
			os.Exit(1)
		}
		// A controller that adopted the previous one's pinned objects
		// detaches what no pod claimed once the pods are reconciled.
		if uprobeMgr.Adopted() {
			if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
				pending := reconciler.WaitForInitialReconcile(ctx, adoptReconcileTimeout)
				if ctx.Err() != nil {
					return nil
				}
				if len(pending) > 0 {
					setupLog.Warnw("pods not reconciled yet: what they had attached may be detached, and attached again once they are",
						"pods", pending, "timeout", adoptReconcileTimeout.String())
				}
				uprobeMgr.FinishAdopt()
				return nil
			})); err != nil {
				setupLog.Errorw("unable to add the eBPF adoption runnable", "error", err)
				_ = setupLog.Sync()
				os.Exit(1)
			}
		}
	}

	setupLog.Infow("starting manager")
	startErr := mgr.Start(signalCtx)
	// Past mgr.Start: signalCtx is done, manager has already given runnables
	// up to GracefulShutdownTimeout to return. Log the trigger so the cause
	// (signal vs runnable error) is unambiguous in post-mortem CI logs.
	if signalCtx.Err() != nil {
		setupLog.Infow("shutdown signal received, draining")
	}
	if startErr != nil {
		setupLog.Errorw("problem running manager", "error", startErr)
	}

	// Flush coverage BEFORE Close: if Close hangs (e.g. a slow link
	// detach pushes us past kubelet's grace period), we still capture
	// coverage of everything up to shutdown. flushCoverage is a no-op
	// in production builds (gated by `//go:build cover`).
	flushCoverage()

	if uprobeMgr != nil {
		mode, why := ebpf.ShutdownDetach, "the data plane is not kept across restarts (no --daemonset)"
		if persist {
			mode, why = shutdownMode(context.Background(), mgr.GetAPIReader(), namespace, daemonSetName, uninstall.Uninstalled())
		}
		setupLog.Infow("shutting down the eBPF data plane", "mode", mode.String(), "reason", why)
		if err := uprobeMgr.Shutdown(mode); err != nil {
			setupLog.Errorw("failed to close uprobe manager", "error", err)
		}
	}
	goruntime.KeepAlive(nodeLock) // an unreachable *os.File is closed by the GC, which would release the lock
	setupLog.Infow("controller exited cleanly")
	_ = setupLog.Sync()
}

// discoverTrustedDNSServers returns the trusted DNS server IPs
// (controller.TrustedDNSServers): kube-dns's ClusterIPs and endpoints, and
// --trusted-dns-servers.
func discoverTrustedDNSServers(reader client.Reader, log *zap.SugaredLogger) []net.IP {
	ips := controller.TrustedDNSServers(context.Background(), reader, parseTrustedDNSServers(trustedDNSServers, log), log)
	for _, ip := range ips {
		log.Infow("Added trusted DNS server", "ip", ip.String())
	}
	if len(ips) == 0 {
		log.Errorw("No trusted DNS servers found — DNS whitelist will reject all DNS responses. " +
			"Ensure kube-dns is running or provide --trusted-dns-servers")
	}
	return ips
}

// parseTrustedDNSServers parses --trusted-dns-servers, skipping (and
// logging) what is not an IP.
func parseTrustedDNSServers(s string, log *zap.SugaredLogger) []net.IP {
	var out []net.IP
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		ip := net.ParseIP(f)
		if ip == nil {
			log.Errorw("Invalid trusted DNS server IP", "ip", f)
			continue
		}
		out = append(out, ip)
	}
	return out
}
