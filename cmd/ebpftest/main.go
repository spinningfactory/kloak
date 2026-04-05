//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"

	ebpfpkg "github.com/spinningfactory/kloak/pkg/ebpf"
)

func main() {
	fmt.Println("Attempting to load eBPF objects...")
	mgr, err := ebpfpkg.NewTLSUprobeManager(nil, "", nil)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "=== VERIFIER ERROR ===\n%+v\n", ve)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
	defer func() { _ = mgr.Close() }()
	fmt.Println("eBPF objects loaded successfully!")
}
