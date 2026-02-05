package main

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/dhia/bouncer/pkg/controller"
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
	Short: "Run the Bouncer controller",
	Long:  `Starts the Kubernetes controller that watches pods and manages eBPF programs.`,
	Run:   runController,
}

var (
	controllerMetricsAddr string
	controllerProbeAddr   string
	enableLeaderElection  bool
	enableEBPF            bool
	cgroupPath            string
)

func init() {
	controllerCmd.Flags().StringVar(&controllerMetricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	controllerCmd.Flags().StringVar(&controllerProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	controllerCmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	controllerCmd.Flags().BoolVar(&enableEBPF, "enable-ebpf", false, "Enable eBPF traffic redirection (requires Linux + CAP_BPF).")
	controllerCmd.Flags().StringVar(&cgroupPath, "cgroup-path", "/sys/fs/cgroup", "Path to cgroup v2 filesystem.")
}

func runController(cmd *cobra.Command, args []string) {
	opts := zap.Options{Development: true}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("Starting Bouncer controller", "ebpf", enableEBPF, "cgroupPath", cgroupPath)

	// Create cgroup manager
	var cgroupMgr controller.CgroupManager
	var ebpfMgr *EBPFCgroupManager

	if enableEBPF {
		var err error
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
		LeaderElectionID:       "bouncer-controller-leader",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create pod reconciler
	reconciler := controller.NewReconciler(
		mgr.GetClient(),
		ctrl.Log.WithName("controller").WithName("Pod"),
		mgr.GetScheme(),
		cgroupMgr,
		cgroupPath,
	)

	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pod")
		os.Exit(1)
	}

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
	if ebpfMgr != nil {
		ebpfMgr.Close()
	}
}
