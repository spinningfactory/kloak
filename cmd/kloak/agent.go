package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/spinningfactory/kloak/pkg/agent"
	"github.com/spinningfactory/kloak/pkg/ebpf"
	"github.com/spinningfactory/kloak/pkg/storage"
	"github.com/spinningfactory/kloak/pkg/sync"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run the Kloak data plane agent",
	Long: `Starts the data plane agent for eBPF uprobe TLS interception.

The agent is responsible for:
- Syncing secrets from the controller via gRPC
- Managing eBPF uprobes to intercept TLS requests
- Managing CNI interactions

The agent connects to the controller to receive secret updates and caches
them locally for low-latency lookups during request processing.`,
	Run: runAgent,
}

var (
	agentControllerAddr string
	agentNamespaces     []string
)

func init() {
	agentCmd.Flags().StringVar(&agentControllerAddr, "controller-addr", "kloak-controller.kloak-system.svc:9090", "The address of the controller's gRPC sync server.")
	agentCmd.Flags().StringSliceVar(&agentNamespaces, "namespaces", nil, "Namespaces to watch (empty for all).")
	rootCmd.AddCommand(agentCmd)
}

func runAgent(cmd *cobra.Command, args []string) {
	opts := zap.Options{Development: true}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	log := ctrl.Log.WithName("agent")
	log.Info("Starting Kloak agent",
		"controllerAddr", agentControllerAddr,
		"namespaces", agentNamespaces,
	)

	// Create local storage for secrets
	store := storage.NewMemory()

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

	// Initialize eBPF TLS uprobe manager
	uprobeMgr, err := ebpf.NewTLSUprobeManager(store)
	if err != nil {
		log.Error(err, "failed to initialize eBPF TLS uprobe manager")
		// Non-fatal for development if bpf fails
	} else {
		defer uprobeMgr.Close()
		go func() {
			if err := uprobeMgr.PollEvents(ctx); err != nil && ctx.Err() == nil {
				log.Error(err, "TLS uprobe event poller failed")
			}
		}()
	}

	// Create and start CNI Server
	cniServer := agent.NewCNIServer(log.WithName("cni"))
	go func() {
		if err := cniServer.Start(ctx); err != nil {
			log.Error(err, "CNI server failed")
			cancel() // Stop everything if CNI server fails
		}
	}()

	// Wait for shutdown (sync and uprobes run in background)
	<-ctx.Done()
	log.Info("Agent shutting down")
}
