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
)

func init() {
	controllerCmd.Flags().StringVar(&controllerProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	controllerCmd.Flags().BoolVar(&enableEBPF, "enable-ebpf", false, "Enable eBPF traffic redirection (requires Linux + CAP_BPF).")
	controllerCmd.Flags().StringVar(&cgroupPath, "cgroup-path", "/sys/fs/cgroup", "Path to cgroup v2 filesystem.")
	controllerCmd.Flags().StringVar(&trustedDNSServers, "trusted-dns-servers", "", "Comma-separated trusted DNS server IPs. If empty, auto-discovers kube-dns.")
}

func runController(cmd *cobra.Command, args []string) {
	setupLog := logging.Setup().Named("setup")

	setupLog.Infow("Starting Kloak controller", "ebpf", enableEBPF, "cgroupPath", cgroupPath)

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
		uprobeMgr, err = ebpf.NewTLSUprobeManager(mgr.GetClient(), cgroupPath, setupLog)
		if err != nil {
			setupLog.Errorw("failed to initialize eBPF uprobe manager", "error", err)
			_ = setupLog.Sync()
			os.Exit(1)
		}
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

	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Errorw("unable to create controller", "error", err, "controller", "Pod")
		_ = setupLog.Sync()
		os.Exit(1)
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

	if uprobeMgr != nil {
		setupLog.Infow("closing uprobe manager")
		closeStart := time.Now()
		if err := uprobeMgr.Close(); err != nil {
			setupLog.Errorw("failed to close uprobe manager", "error", err)
		}
		setupLog.Infow("uprobe manager closed", "duration", time.Since(closeStart).String())
	}
	setupLog.Infow("controller exited cleanly")
	_ = setupLog.Sync()
}

// discoverTrustedDNSServers returns the list of trusted DNS server IPs.
// Always includes the kube-dns ClusterIP (auto-discovered). If
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
	} else if ip := net.ParseIP(svc.Spec.ClusterIP); ip != nil {
		addIP(ip, "kube-dns auto-discovery")
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
