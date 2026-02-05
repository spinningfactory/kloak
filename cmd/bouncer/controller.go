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

// MockCgroupManager is a placeholder - in production this would interface with eBPF
type MockCgroupManager struct{}

func (m *MockCgroupManager) AddCgroup(cgroupID uint64) error {
	ctrl.Log.Info("would add cgroup", "cgroupID", cgroupID)
	return nil
}

func (m *MockCgroupManager) RemoveCgroup(cgroupID uint64) error {
	ctrl.Log.Info("would remove cgroup", "cgroupID", cgroupID)
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
)

func init() {
	controllerCmd.Flags().StringVar(&controllerMetricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	controllerCmd.Flags().StringVar(&controllerProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	controllerCmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
}

func runController(cmd *cobra.Command, args []string) {
	opts := zap.Options{Development: true}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("Starting Bouncer controller")

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
		&MockCgroupManager{},
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
		os.Exit(1)
	}
}
