package main

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/spinningfactory/kloak/pkg/webhook"
)

var certGenCmd = &cobra.Command{
	Use:   "cert-gen",
	Short: "Generate webhook TLS certificates",
	Long:  "Generates self-signed TLS certificates for the mutating webhook, stores them in a Kubernetes Secret, and patches the MutatingWebhookConfiguration with the CA bundle.",
	Run:   runCertGen,
}

var certGenNamespace string

func init() {
	certGenCmd.Flags().StringVar(&certGenNamespace, "namespace", "", "Namespace for the webhook cert secret (defaults to POD_NAMESPACE env or kloak-system).")
}

func runCertGen(cmd *cobra.Command, args []string) {
	opts := zap.Options{Development: true}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("cert-gen")

	if certGenNamespace == "" {
		certGenNamespace = os.Getenv("POD_NAMESPACE")
	}
	if certGenNamespace == "" {
		certGenNamespace = "kloak-system"
	}

	log.Info("Generating webhook TLS certificates", "namespace", certGenNamespace)

	k8sConfig := ctrl.GetConfigOrDie()
	c, err := client.New(k8sConfig, client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "failed to create Kubernetes client")
		os.Exit(1)
	}

	_, err = webhook.EnsureWebhookCerts(context.Background(), c, certGenNamespace)
	if err != nil {
		log.Error(err, "failed to ensure webhook certificates")
		os.Exit(1)
	}

	log.Info("Webhook TLS certificates ready")
}
