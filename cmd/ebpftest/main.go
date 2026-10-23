//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	ebpfpkg "github.com/spinningfactory/kloak/pkg/ebpf"
)

func main() {
	fmt.Println("Attempting to load eBPF objects...")
	ranges, err := ebpfpkg.ParseVirtualIPRanges(ebpfpkg.DefaultVirtualIPRange)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	// Its own pin directory, so the maps of a controller on this node are
	// left alone.
	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "kloak-ebpftest-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: creating a pin directory on bpffs: %v\n", err)
		os.Exit(1)
	}
	hostRes := &ebpfpkg.HostResolutionConfig{VirtualIPRanges: ranges, PinPath: pinPath}
	// The connect redirect attaches to the kubepods cgroup: on a host
	// without one, the objects load but the manager fails after.
	mgr, err := ebpfpkg.NewTLSUprobeManager(nil, "/sys/fs/cgroup", "auto", hostRes, zap.NewNop().Sugar())
	if err != nil {
		_ = os.RemoveAll(pinPath)
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "=== VERIFIER ERROR ===\n%+v\n", ve)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
	_ = mgr.Close()
	_ = os.RemoveAll(pinPath)
	fmt.Println("eBPF objects loaded successfully!")
}
