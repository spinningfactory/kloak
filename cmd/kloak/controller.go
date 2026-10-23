package main

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
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
	hostResolution      string
	virtualIPRange      string
	nriSocket           string
)

func init() {
	controllerCmd.Flags().StringVar(&controllerProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	controllerCmd.Flags().BoolVar(&enableEBPF, "enable-ebpf", false, "Enable eBPF traffic redirection (requires Linux + CAP_BPF).")
	controllerCmd.Flags().StringVar(&cgroupPath, "cgroup-path", "/sys/fs/cgroup", "Path to cgroup v2 filesystem.")
	controllerCmd.Flags().StringVar(&trustedDNSServers, "trusted-dns-servers", "", "Comma-separated trusted DNS server IPs. If empty, auto-discovers kube-dns.")
	controllerCmd.Flags().StringVar(&egressInterface, "egress-interface", "auto",
		"Container interface whose host-side veth peer gets the tc patch program (tc ingress). "+
			`"auto" detects from the default IPv4 route in the container netns (works for CNI veth "eth0" AND host-mode netns with non-standard names like wlp3s0/enp0s3). `+
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
	controllerCmd.Flags().StringVar(&hostResolution, "host-resolution", string(ebpf.HostResolutionDNSSnoop),
		`How the data plane works out which host a connection goes to, for secrets restricted to a hostname (getkloak.io/hosts). `+
			`"dns-snoop" reads DNS answers as pods receive them (IPv4 connections only). "virtual-ip" (experimental, spinningfactory/kloak#327) gives every such host a stable fake IP, and fake IPv6, from --virtual-ip-range, `+
			`kept in maps pinned under `+ebpf.DefaultBPFPinPath+`. A kloak pod with a secret for the host gets the fake IP in DNS answers and its connects to it are redirected to the host's addresses; a host-restricted secret is only rewritten on a connection made to its host's fake IP.`)
	controllerCmd.Flags().StringVar(&nriSocket, "nri-socket", controller.DefaultNRISocket,
		`NRI socket of the container runtime (containerd 2.0+, CRI-O 1.30+), used with --host-resolution=virtual-ip: the runtime then waits for kloak to attach the DNS rewrite while it creates each pod sandbox, before the pod's containers start. `+
			`Without NRI (unreachable socket, or "" to disable), the rewrite is attached by polling pending pods, which leaves a short window at pod start in which a lookup gets the real addresses and a connection made with them no host-restricted secret.`)
	controllerCmd.Flags().StringVar(&virtualIPRange, "virtual-ip-range", ebpf.DefaultVirtualIPRange,
		`Ranges fake IPs come from with --host-resolution=virtual-ip: an IPv4 range (/19 or larger) and, optionally, an IPv6 one (/115 or larger), comma-separated. `+
			`Without an IPv6 range, AAAA answers are left unchanged. `+
			`The controller refuses to start if a range overlaps a node address, pod CIDR, service CIDR or route of the node.`)
}

func runController(cmd *cobra.Command, args []string) {
	setupLog := logging.Setup().Named("setup")

	setupLog.Infow("Starting Kloak controller", "ebpf", enableEBPF, "cgroupPath", cgroupPath, "egressInterface", egressInterface, "tcAttachMode", tcAttachMode, "secretBinding", secretBinding, "sniCheck", sniCheck, "hostResolution", hostResolution, "nriSocket", nriSocket)

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
	hostResMode, err := ebpf.ParseHostResolutionMode(hostResolution)
	if err != nil {
		setupLog.Errorw("invalid --host-resolution", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}
	hostRes := ebpf.HostResolutionConfig{Mode: hostResMode}
	if hostResMode == ebpf.HostResolutionVirtualIP {
		hostRes.VirtualIPRanges, err = ebpf.ParseVirtualIPRanges(virtualIPRange)
		if err != nil {
			setupLog.Errorw("invalid --virtual-ip-range", "error", err)
			_ = setupLog.Sync()
			os.Exit(1)
		}
	}

	// 30 s is well under the daemonset's 60 s terminationGracePeriodSeconds,
	// leaving headroom for our own cleanup (uprobe/link Close) and any final
	// log flush before kubelet's SIGKILL. Without this the manager defaults
	// to 30 s anyway, but pinning it documents the budget and makes it
	// obvious where to tune if shutdown ever pushes past the grace period.
	gracefulShutdown := 30 * time.Second
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		HealthProbeBindAddress:  controllerProbeAddr,
		GracefulShutdownTimeout: &gracefulShutdown,
	})
	if err != nil {
		setupLog.Errorw("unable to start manager", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}

	// Create uprobe manager instances
	var uprobeMgr *ebpf.TLSUprobeManager

	if enableEBPF {
		if hostResMode == ebpf.HostResolutionVirtualIP {
			// The controller runs with hostPID: /proc/1 is in the host
			// network namespace.
			checkCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := checkVirtualIPRanges(checkCtx, mgr.GetAPIReader(), hostRes.VirtualIPRanges, "/proc/1", setupLog)
			cancel()
			if err != nil {
				setupLog.Errorw("invalid --virtual-ip-range", "error", err)
				_ = setupLog.Sync()
				os.Exit(1)
			}
		} else {
			ebpf.RemoveVirtualIPPins(hostRes.PinPath, setupLog)
		}
		uprobeMgr, err = ebpf.NewTLSUprobeManager(k8ssecrets.NewSource(mgr.GetClient()).WithLog(setupLog), cgroupPath, egressInterface, &hostRes, setupLog)
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
	// attached before a pod's containers start; without it, the reconciler
	// polls pending pods. Added as a runnable so it starts after the cache
	// sync (PrepareSandbox reads pods from the cache).
	if uprobeMgr != nil && uprobeMgr.VirtualIPEnabled() && nriSocket != "" {
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

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Errorw("unable to set up health check", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Errorw("unable to set up ready check", "error", err)
		_ = setupLog.Sync()
		os.Exit(1)
	}

	// Configure trusted DNS servers for the eBPF DNS chain of trust.
	if uprobeMgr != nil {
		dnsIPs := discoverTrustedDNSServers(mgr.GetAPIReader(), setupLog)
		if err := uprobeMgr.PopulateTrustedDNSServers(dnsIPs); err != nil {
			setupLog.Errorw("failed to populate trusted DNS servers", "error", err)
		}
	}

	// Register eBPF pollers as manager runnables so they start after the
	// informer cache is synced. Starting them before mgr.Start() would cause
	// "cache is not started" errors when syncing secrets to the BPF map.
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
	}

	setupLog.Infow("starting manager")
	signalCtx := ctrl.SetupSignalHandler()
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
		if err := uprobeMgr.Close(); err != nil {
			setupLog.Errorw("failed to close uprobe manager", "error", err)
		}
	}
	setupLog.Infow("controller exited cleanly")
	_ = setupLog.Sync()
}

// discoverTrustedDNSServers returns the list of trusted DNS server IPs.
// Always includes the kube-dns ClusterIPs (auto-discovered): both of a
// dual-stack kube-dns, which pods are given both of as nameservers (musl
// queries them in parallel and takes the first answer). If
// --trusted-dns-servers is set, those are added too (deduplicated).
func discoverTrustedDNSServers(reader client.Reader, log *zap.SugaredLogger) []net.IP {
	seen := make(map[string]bool)
	var ips []net.IP

	addIP := func(ip net.IP, source string) {
		key := ip.String()
		if seen[key] {
			return
		}
		seen[key] = true
		ips = append(ips, ip)
		log.Infow("Added trusted DNS server", "ip", key, "source", source)
	}

	// Always auto-discover kube-dns
	svc := &corev1.Service{}
	err := reader.Get(context.Background(), types.NamespacedName{
		Name:      "kube-dns",
		Namespace: "kube-system",
	}, svc)
	if err != nil {
		log.Errorw("Failed to auto-discover kube-dns service", "error", err)
	} else {
		clusterIPs := svc.Spec.ClusterIPs
		if len(clusterIPs) == 0 {
			clusterIPs = []string{svc.Spec.ClusterIP}
		}
		for _, s := range clusterIPs {
			if ip := net.ParseIP(s); ip != nil { // not "None" (headless)
				addIP(ip, "kube-dns auto-discovery")
			}
		}
	}

	// Add user-provided DNS servers
	if trustedDNSServers != "" {
		for _, s := range strings.Split(trustedDNSServers, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			ip := net.ParseIP(s)
			if ip == nil {
				log.Errorw("Invalid trusted DNS server IP", "ip", s)
				continue
			}
			addIP(ip, "user-configured")
		}
	}

	if len(ips) == 0 {
		log.Errorw("No trusted DNS servers found — DNS whitelist will reject all DNS responses. " +
			"Ensure kube-dns is running or provide --trusted-dns-servers")
	}

	return ips
}
