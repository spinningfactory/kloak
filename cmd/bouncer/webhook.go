package main

import (
	"context"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/dhia/bouncer/pkg/ca"
	"github.com/dhia/bouncer/pkg/storage"
	webhookpkg "github.com/dhia/bouncer/pkg/webhook"
)

var webhookScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(webhookScheme))
}

var webhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "Run the Bouncer mutating admission webhook",
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
	setupLog.Info("Starting Bouncer webhook")

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

	// Load Root CA to inject into pods
	// We need a direct client to access Secrets before the manager cache is started
	k8sConfig := ctrl.GetConfigOrDie()
	directClient, err := client.New(k8sConfig, client.Options{Scheme: webhookScheme})
	if err != nil {
		setupLog.Error(err, "failed to create direct client for CA loading")
		os.Exit(1)
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "bouncer-system"
	}

	caStore := ca.NewStore(directClient, namespace)
	// Use Get to enforce Controller ownership of CA.
	// Webhook will crash-loop until Controller has created the CA.
	rootCA, err := caStore.Get(context.Background())
	if err != nil {
		setupLog.Error(err, "failed to load Root CA - ensure Controller is running first")
		os.Exit(1)
	}
	setupLog.Info("Loaded Root CA for injection", "commonName", rootCA.Cert.Subject.CommonName)

	// Register webhook
	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/mutate-pods", &webhook.Admission{
		Handler: webhookpkg.NewHandler(mgr.GetClient(), store, envList, "http://bouncer-controller.bouncer-system.svc:8090/store", rootCA.CertPEM, setupLog),
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
