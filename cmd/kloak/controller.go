package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/spinningfactory/kloak/pkg/ca"
	"github.com/spinningfactory/kloak/pkg/certs"
	"github.com/spinningfactory/kloak/pkg/controller"
	"github.com/spinningfactory/kloak/pkg/storage"
	"github.com/spinningfactory/kloak/pkg/sync"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

// MockCgroupManager is used when eBPF is disabled or not available.
type MockCgroupManager struct{}

func (m *MockCgroupManager) AddCgroup(cgroupID uint64) error {
	ctrl.Log.Info("mock: would add cgroup", "cgroupID", cgroupID)
	return nil
}

func (m *MockCgroupManager) RemoveCgroup(cgroupID uint64) error {
	ctrl.Log.Info("mock: would remove cgroup", "cgroupID", cgroupID)
	return nil
}

var controllerCmd = &cobra.Command{
	Use:   "controller",
	Short: "Run the Kloak controller",
	Long: `Starts the Kubernetes controller that watches pods and secrets,
manages eBPF programs, and serves the gRPC sync API for agents.

The controller is responsible for:
- Watching K8s Secrets with kloak.io/managed label
- Managing the Root CA for TLS interception
- Managing eBPF cgroup tracking for labeled pods
- Serving the sync gRPC API so agents can receive secret updates`,
	Run: runController,
}

var (
	controllerMetricsAddr string
	controllerProbeAddr   string
	controllerSyncAddr    string
	enableLeaderElection  bool
	enableEBPF            bool
	cgroupPath            string
	certMode              string
)

func init() {
	controllerCmd.Flags().StringVar(&controllerMetricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	controllerCmd.Flags().StringVar(&controllerProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	controllerCmd.Flags().StringVar(&controllerSyncAddr, "sync-address", ":9090", "The address the gRPC sync server binds to.")
	controllerCmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	controllerCmd.Flags().BoolVar(&enableEBPF, "enable-ebpf", false, "Enable eBPF traffic redirection (requires Linux + CAP_BPF).")
	controllerCmd.Flags().StringVar(&cgroupPath, "cgroup-path", "/sys/fs/cgroup", "Path to cgroup v2 filesystem.")
	controllerCmd.Flags().StringVar(&certMode, "cert-mode", "auto", "Certificate mode: 'auto' (generate if missing) or 'provided' (expect existing secrets).")
}

func runController(cmd *cobra.Command, args []string) {
	opts := zap.Options{Development: true}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("Starting Kloak controller", "ebpf", enableEBPF, "cgroupPath", cgroupPath)

	// Create shared storage
	store := storage.NewMemory()

	// Load or Generate CA using K8s Secret
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "kloak-system"
	}

	// We need a direct client to access Secrets before the manager cache is started
	k8sConfig := ctrl.GetConfigOrDie()
	directClient, err := client.New(k8sConfig, client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "failed to create direct client")
		os.Exit(1)
	}

	// Handle certificate mode
	if certMode == "" {
		certMode = os.Getenv("KLOAK_CERT_MODE")
	}
	if certMode == "" {
		certMode = "auto"
	}
	setupLog.Info("Certificate mode", "mode", certMode)

	if certMode == "auto" {
		// Auto-generate certificates if missing
		_, err := certs.EnsureCerts(context.Background(), directClient, namespace, setupLog)
		if err != nil {
			setupLog.Error(err, "failed to ensure certificates")
			os.Exit(1)
		}
	}

	caStore := ca.NewStore(directClient, namespace)
	rootCA, err := caStore.GetOrCreate(context.Background())
	if err != nil {
		setupLog.Error(err, "failed to get or create CA")
		os.Exit(1)
	}
	setupLog.Info("CA loaded successfully", "commonName", rootCA.Cert.Subject.CommonName)

	// Create cgroup manager
	var cgroupMgr controller.CgroupManager
	var ebpfMgr *EBPFCgroupManager

	if enableEBPF {
		ebpfMgr, err = NewEBPFCgroupManager(cgroupPath)
		if err != nil {
			setupLog.Error(err, "failed to initialize eBPF, falling back to mock")
			cgroupMgr = &MockCgroupManager{}
		} else {
			cgroupMgr = ebpfMgr
			setupLog.Info("eBPF traffic redirection enabled")
		}
	} else {
		setupLog.Info("eBPF disabled, using mock cgroup manager")
		cgroupMgr = &MockCgroupManager{}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: controllerProbeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "kloak-controller-leader",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create gRPC Sync Server (replaces XDS in controller)
	syncServer := sync.NewServer(store, ctrl.Log.WithName("sync"))

	// Start gRPC server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := startSyncServer(ctx, controllerSyncAddr, syncServer, setupLog); err != nil {
			setupLog.Error(err, "sync server failed")
		}
	}()

	// Create HTTP Server for webhook to store hashes (legacy, will migrate to gRPC)
	httpServer := controller.NewServer(store, ctrl.Log.WithName("http"))

	// Start HTTP server immediately in goroutine (don't wait for leader election)
	// This ensures webhook can send hashes during pod admission
	go func() {
		setupLog.Info("starting HTTP server immediately (before leader election)")
		if err := httpServer.Start(ctx, ":8090"); err != nil {
			setupLog.Error(err, "HTTP server failed")
		}
	}()

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
		cgroupMgr,
		cgroupPath,
		nodeName,
	)

	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pod")
		os.Exit(1)
	}

	// Create secret reconciler with sync server for notifications
	secretReconciler := &controller.SecretReconciler{
		Client:     mgr.GetClient(),
		Log:        ctrl.Log.WithName("controller").WithName("Secret"),
		Scheme:     mgr.GetScheme(),
		Storage:    store,
		SyncServer: syncServer,
	}

	if err := secretReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Secret")
		os.Exit(1)
	}

	// Create CA reconciler to sync ConfigMap to labeled namespaces
	caProvider := ca.NewProvider(rootCA, ctrl.Log.WithName("ca-provider"))
	caReconciler := &ca.Reconciler{
		Client:         mgr.GetClient(),
		Provider:       caProvider,
		Namespace:      namespace,
		Log:            ctrl.Log.WithName("controller").WithName("CA"),
		SyncNamespaces: true, // Enable ConfigMap sync to labeled namespaces
	}

	if err := caReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CA")
		os.Exit(1)
	}
	setupLog.Info("CA reconciler configured", "syncNamespaces", true)

	// Add health checks
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		if ebpfMgr != nil {
			ebpfMgr.Close()
		}
		os.Exit(1)
	}

	// Cleanup
	cancel()
	if ebpfMgr != nil {
		ebpfMgr.Close()
	}
}

// startSyncServer starts the gRPC sync server.
func startSyncServer(ctx context.Context, addr string, syncServer *sync.Server, log logr.Logger) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	grpcServer := grpc.NewServer()
	syncServer.Register(grpcServer)

	log.Info("starting gRPC sync server", "addr", addr)

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	return grpcServer.Serve(lis)
}

// runnableFunc helper for manager.Runnable
type runnableFunc func(context.Context) error

func (r runnableFunc) Start(ctx context.Context) error {
	return r(ctx)
}
