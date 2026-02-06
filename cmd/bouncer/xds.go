package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/dhia/bouncer/pkg/ca"
	"github.com/dhia/bouncer/pkg/storage"
	"github.com/dhia/bouncer/pkg/xds"
)

var xdsCmd = &cobra.Command{
	Use:   "xds",
	Short: "Run the XDS server (SDS + ext_proc)",
	Long:  `Starts the gRPC server that provides Secret Discovery Service and External Processor for Envoy sidecars.`,
	Run:   runXDS,
}

var (
	xdsAddr string
)

func init() {
	xdsCmd.Flags().StringVar(&xdsAddr, "addr", ":15002", "The address the XDS server binds to.")
	rootCmd.AddCommand(xdsCmd)
}

func runXDS(cmd *cobra.Command, args []string) {
	opts := zap.Options{Development: true}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	log := ctrl.Log.WithName("xds")
	log.Info("Starting Bouncer XDS server")

	// Check if CA files exist
	caCertPath := "/etc/bouncer/ca/tls.crt"
	caKeyPath := "/etc/bouncer/ca/tls.key"
	var rootCA *ca.CA
	var err error

	if _, err = os.Stat(caCertPath); err == nil {
		log.Info("Loading CA from file", "path", caCertPath)
		certPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			log.Error(err, "failed to read CA cert")
			os.Exit(1)
		}
		keyPEM, err := os.ReadFile(caKeyPath)
		if err != nil {
			log.Error(err, "failed to read CA key")
			os.Exit(1)
		}
		rootCA, err = ca.LoadCA(certPEM, keyPEM)
		if err != nil {
			log.Error(err, "failed to parse CA")
			os.Exit(1)
		}
	} else {
		log.Info("CA file not found, generating new CA (for testing)")
		rootCA, err = ca.GenerateCA("Bouncer Root CA", 365*24*time.Hour)
		if err != nil {
			log.Error(err, "failed to generate CA")
			os.Exit(1)
		}
	}
	log.Info("Root CA loaded/generated", "cn", rootCA.Cert.Subject.CommonName)

	// Create storage
	store := storage.NewMemory()

	// Create XDS server
	server := xds.NewServer(rootCA, store, log)

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Info("Received shutdown signal")
		cancel()
	}()

	log.Info("Starting XDS server", "addr", xdsAddr)
	if err := server.Run(ctx, xdsAddr); err != nil {
		log.Error(err, "XDS server failed")
		os.Exit(1)
	}
}
