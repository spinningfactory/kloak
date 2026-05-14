//go:build !linux

// Non-Linux stub for the ebpftest CLI. The real implementation in
// main.go loads kloak's eBPF objects via `github.com/cilium/ebpf` to
// surface the verifier output, which only works on Linux. This stub
// exists solely so `go build ./...` and `go vet ./...` succeed on
// macOS / other dev environments.

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ebpftest is Linux-only.")
	os.Exit(1)
}
