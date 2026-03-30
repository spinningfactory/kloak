package main

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/spinningfactory/kloak/pkg/controller"
	"github.com/spinningfactory/kloak/pkg/ebpf"
	"github.com/spinningfactory/kloak/pkg/storage"
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
	opts := zap.Options{Development: true}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("Starting Kloak controller", "ebpf", enableEBPF, "cgroupPath", cgroupPath)

	// Create shared storage
	store := storage.NewMemory()

	// Create uprobe manager instances
	var uprobeMgr *ebpf.TLSUprobeManager
	var err error

	if enableEBPF {
		uprobeMgr, err = ebpf.NewTLSUprobeManager(store, cgroupPath)
		if err != nil {
			setupLog.Error(err, "failed to initialize eBPF uprobe manager")
			os.Exit(1)
		}
		setupLog.Info("eBPF TLS uprobes enabled")
	} else {
		setupLog.Info("eBPF disabled")
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: controllerProbeAddr,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create pod reconciler
	// NODE_NAME is used to filter pods to only those on this node (DaemonSet per-node controller)
	nodeName := os.Getenv("NODE_NAME")
	if nodeName != "" {
		setupLog.Info("Node filtering enabled", "nodeName", nodeName)
	}
	reconciler := controller.NewReconciler(
		mgr.GetClient(),
		ctrl.Log.WithName("controller").WithName("Pod"),
		mgr.GetScheme(),
		uprobeMgr,
		cgroupPath,
		nodeName,
	)

	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pod")
		os.Exit(1)
	}

	// Create secret reconciler
	secretReconciler := &controller.SecretReconciler{
		Client:  mgr.GetClient(),
		Log:     ctrl.Log.WithName("controller").WithName("Secret"),
		Scheme:  mgr.GetScheme(),
		Storage: store,
	}

	if err := secretReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Secret")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Configure trusted DNS servers for the eBPF DNS chain of trust.
	if uprobeMgr != nil {
		dnsIPs := discoverTrustedDNSServers(mgr.GetAPIReader(), setupLog)
		if err := uprobeMgr.PopulateTrustedDNSServers(dnsIPs); err != nil {
			setupLog.Error(err, "failed to populate trusted DNS servers")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start eBPF TLS event poller (syncs secrets to BPF map and reads events)
	if uprobeMgr != nil {
		go func() {
			if err := uprobeMgr.PollEvents(ctx); err != nil && ctx.Err() == nil {
				setupLog.Error(err, "eBPF TLS event poller failed")
			}
		}()
		go func() {
			if err := uprobeMgr.PollExecEvents(ctx); err != nil && ctx.Err() == nil {
				setupLog.Error(err, "eBPF process exec event poller failed")
			}
		}()
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
	}

	// Cleanup
	cancel()
	if uprobeMgr != nil {
		if err := uprobeMgr.Close(); err != nil {
			setupLog.Error(err, "failed to close uprobe manager")
		}
	}
}

// discoverTrustedDNSServers returns the list of trusted DNS server IPs.
// Always includes the kube-dns ClusterIP (auto-discovered). If
// --trusted-dns-servers is set, those are added too (deduplicated).
func discoverTrustedDNSServers(reader client.Reader, log logr.Logger) []net.IP {
	seen := make(map[string]bool)
	var ips []net.IP

	addIP := func(ip net.IP, source string) {
		key := ip.String()
		if seen[key] {
			return
		}
		seen[key] = true
		ips = append(ips, ip)
		log.Info("Added trusted DNS server", "ip", key, "source", source)
	}

	// Always auto-discover kube-dns
	svc := &corev1.Service{}
	err := reader.Get(context.Background(), types.NamespacedName{
		Name:      "kube-dns",
		Namespace: "kube-system",
	}, svc)
	if err != nil {
		log.Error(err, "Failed to auto-discover kube-dns service")
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
				log.Error(nil, "Invalid trusted DNS server IP", "ip", s)
				continue
			}
			addIP(ip, "user-configured")
		}
	}

	if len(ips) == 0 {
		log.Error(nil, "No trusted DNS servers found — DNS whitelist will reject all DNS responses. "+
			"Ensure kube-dns is running or provide --trusted-dns-servers")
	}

	return ips
}
