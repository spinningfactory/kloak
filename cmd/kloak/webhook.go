package main

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/spinningfactory/kloak/pkg/storage"
	webhookpkg "github.com/spinningfactory/kloak/pkg/webhook"
)

var webhookScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(webhookScheme))
}

var webhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "Run the Kloak mutating admission webhook",
	Long:  `Starts the admission webhook that injects Envoy sidecars and hashes environment variables.`,
	Run:   runWebhook,
}

var (
	webhookProbeAddr  string
	webhookCertDir    string
	webhookEnvsToHash string
)

func init() {
	webhookCmd.Flags().StringVar(&webhookProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	webhookCmd.Flags().StringVar(&webhookCertDir, "cert-dir", "/certs", "Directory containing TLS certs.")
	webhookCmd.Flags().StringVar(&webhookEnvsToHash, "hash-envs", "API_KEY,SECRET_KEY,PASSWORD,TOKEN,OPENAI_API_KEY", "Comma-separated env var names to hash.")
}

func runWebhook(cmd *cobra.Command, args []string) {
	opts := zap.Options{Development: true}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("Starting Kloak webhook")

	// Parse env vars to hash
	envList := parseEnvList(webhookEnvsToHash)
	setupLog.Info("Will hash environment variables", "envs", envList)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 webhookScheme,
		HealthProbeBindAddress: webhookProbeAddr,
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    9443,
			CertDir: webhookCertDir,
		}),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create storage (in-memory for now)
	store := storage.NewMemory()

	// No longer need to load CA here - pods mount the CA ConfigMap directly
	// The controller syncs the kloak-ca-cert ConfigMap to labeled namespaces
	setupLog.Info("Webhook using ConfigMap-based CA distribution", "configmap", "kloak-ca-cert")

	// Register webhook
	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/mutate-pods", &webhook.Admission{
		Handler: webhookpkg.NewHandler(mgr.GetClient(), store, envList, "http://kloak-controller.kloak-system.svc:8090/store", setupLog),
	})

	// Add health checks
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting webhook server")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func parseEnvList(envs string) []string {
	if envs == "" {
		return nil
	}
	return strings.Split(envs, ",")
}
