package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/spinningfactory/kloak/pkg/ca"
	"github.com/spinningfactory/kloak/pkg/storage"
	"github.com/spinningfactory/kloak/pkg/sync"
	"github.com/spinningfactory/kloak/pkg/xds"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run the Kloak data plane agent",
	Long: `Starts the data plane agent that serves XDS/SDS/ExtProc for Envoy sidecars.

The agent is responsible for:
- Serving the XDS API (LDS, CDS) to configure Envoy sidecars
- Serving the SDS API for dynamic TLS certificate generation
- Running the ExtProc server for header rewriting
- Syncing secrets from the controller via gRPC

The agent connects to the controller to receive secret updates and caches
them locally for low-latency lookups during request processing.`,
	Run: runAgent,
}

var (
	agentXDSAddr        string
	agentControllerAddr string
	agentNamespaces     []string
)

func init() {
	agentCmd.Flags().StringVar(&agentXDSAddr, "xds-addr", ":15002", "The address the XDS server binds to.")
	agentCmd.Flags().StringVar(&agentControllerAddr, "controller-addr", "kloak-controller.kloak-system.svc:9090", "The address of the controller's gRPC sync server.")
	agentCmd.Flags().StringSliceVar(&agentNamespaces, "namespaces", nil, "Namespaces to watch (empty for all).")
	rootCmd.AddCommand(agentCmd)
}

func runAgent(cmd *cobra.Command, args []string) {
	opts := zap.Options{Development: true}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	log := ctrl.Log.WithName("agent")
	log.Info("Starting Kloak agent",
		"xdsAddr", agentXDSAddr,
		"controllerAddr", agentControllerAddr,
		"namespaces", agentNamespaces,
	)

	// Create local storage for secrets
	store := storage.NewMemory()

	// Load CA (from file or generate for testing)
	rootCA, err := loadAgentCA(log)
	if err != nil {
		log.Error(err, "failed to load CA")
		os.Exit(1)
	}
	log.Info("CA loaded", "cn", rootCA.Cert.Subject.CommonName)

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

	// Create sync client to receive secrets from controller
	syncClient := sync.NewClient(agentControllerAddr, store, log.WithName("sync"))
	syncClient.SetNamespaceFilter(agentNamespaces)

	// Start sync client in background (reconnects automatically)
	go func() {
		if err := syncClient.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error(err, "sync client failed")
		}
	}()

	// Create XDS server (serves LDS, SDS, ExtProc)
	xdsServer := xds.NewServer(rootCA, store, log.WithName("xds"))

	// Run XDS server
	log.Info("Starting XDS server", "addr", agentXDSAddr)
	if err := xdsServer.Run(ctx, agentXDSAddr); err != nil && ctx.Err() == nil {
		log.Error(err, "XDS server failed")
		os.Exit(1)
	}
}

// loadAgentCA loads the CA from files, waiting for them to appear if necessary.
func loadAgentCA(log logr.Logger) (*ca.CA, error) {
	caCertPath := "/etc/kloak/ca/tls.crt"
	caKeyPath := "/etc/kloak/ca/tls.key"

	// Wait up to 2 minutes for CA certs to appear (created by controller)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		if _, err := os.Stat(caCertPath); err == nil {
			log.Info("Loading CA from file", "path", caCertPath)
			certPEM, err := os.ReadFile(caCertPath)
			if err != nil {
				return nil, err
			}
			keyPEM, err := os.ReadFile(caKeyPath)
			if err != nil {
				return nil, err
			}
			return ca.LoadCA(certPEM, keyPEM)
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for CA file at %s", caCertPath)
		case <-ticker.C:
			log.Info("Waiting for CA file...", "path", caCertPath)
		}
	}
}
