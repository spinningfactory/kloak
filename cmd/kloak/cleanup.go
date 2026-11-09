package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/spinningfactory/kloak/pkg/ebpf"
	"github.com/spinningfactory/kloak/pkg/logging"
)

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Remove the eBPF programs and maps kloak left on this node",
	Long: `Detaches the eBPF programs a kloak controller left attached on this node,
and removes the maps and programs it pinned (` + ebpf.DefaultBPFPinPath + `), as an uninstall does.

The controllers keep their node's data plane attached across restarts, and
tear it down when kloak is uninstalled. Run this on a node they could not
reach then (down during the uninstall, or no longer in the controller
DaemonSet's scope), as root in the host's mount namespace, for example:

  nsenter -t 1 -m -- /path/to/kloak cleanup

A reboot does the same: bpffs is in memory.`,
	Run: runCleanup,
}

var (
	cleanupPinPath  string
	cleanupNodeLock string
	cleanupWait     time.Duration
)

func init() {
	cleanupCmd.Flags().StringVar(&cleanupPinPath, "pin-path", ebpf.DefaultBPFPinPath, "bpffs directory kloak pins its eBPF objects in.")
	cleanupCmd.Flags().StringVar(&cleanupNodeLock, "node-lock", DefaultNodeLock, `Node lock the controllers hold ("" to skip): the cleanup refuses to run while a controller runs on the node.`)
	cleanupCmd.Flags().DurationVar(&cleanupWait, "wait", 10*time.Second, "How long to wait for the node lock.")
	rootCmd.AddCommand(cleanupCmd)
}

func runCleanup(_ *cobra.Command, _ []string) {
	log := logging.Setup().Named("cleanup")
	var nodeLock *os.File
	if cleanupNodeLock != "" {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupWait)
		var err error
		nodeLock, err = lockNode(ctx, cleanupNodeLock, log)
		cancel()
		if err != nil {
			log.Errorw("a kloak controller runs on this node (it holds the node lock): stop it first", "error", err)
			_ = log.Sync()
			os.Exit(1)
		}
	}
	if err := ebpf.CleanupPins(cleanupPinPath, log); err != nil {
		log.Errorw("removing kloak's eBPF objects failed", "pinPath", cleanupPinPath, "error", err)
		_ = log.Sync()
		os.Exit(1)
	}
	fmt.Printf("kloak's eBPF objects are removed from %s\n", cleanupPinPath)
	_ = log.Sync()
	runtime.KeepAlive(nodeLock) // held through the cleanup: an unreachable *os.File is closed by the GC
}
