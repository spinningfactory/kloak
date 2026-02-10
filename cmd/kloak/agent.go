package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/spinningfactory/kloak/pkg/agent"
	"github.com/spinningfactory/kloak/pkg/ca"
	"github.com/spinningfactory/kloak/pkg/ebpf"
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

	// Initialize eBPF manager (shared with CNI server)
	// We need it to add pods to the map when CNI calls us.
	// For now, we assume standard cgroup path.
	cgroupPath := "/sys/fs/cgroup"
	ebpfMgr, err := ebpf.NewEBPFCgroupManager(cgroupPath)
	if err != nil {
		log.Error(err, "failed to initialize eBPF manager")
		os.Exit(1)
	}
	defer ebpfMgr.Close()

	// Create and start CNI Server
	cniServer := agent.NewCNIServer(log.WithName("cni"), ebpfMgr)
	go func() {
		if err := cniServer.Start(ctx); err != nil {
			log.Error(err, "CNI server failed")
			cancel() // Stop everything if CNI server fails
		}
	}()

	// Run XDS server
	log.Info("Starting XDS server", "addr", agentXDSAddr)
	if err := xdsServer.Run(ctx, agentXDSAddr); err != nil && ctx.Err() == nil {
		log.Error(err, "XDS server failed")
		os.Exit(1)
	}
}

// loadAgentCA loads the CA from files.
// It assumes the CA files are already present (e.g. ensured by an init container).
func loadAgentCA(log logr.Logger) (*ca.CA, error) {
	caCertPath := "/etc/kloak/ca/tls.crt"
	caKeyPath := "/etc/kloak/ca/tls.key"

	log.Info("Loading CA from file", "path", caCertPath)
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert at %s: %w", caCertPath, err)
	}
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key at %s: %w", caKeyPath, err)
	}

	return ca.LoadCA(certPEM, keyPEM)
}
