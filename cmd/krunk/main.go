// Command krunk is kloak's host-CLI runtime. It wraps a child process
// in a transient cgroup with kloak's eBPF data plane active so the
// child's shadow placeholders get rewritten to real values on outbound
// TLS — same end state as a kloak-enabled Pod, no Kubernetes needed.
//
// The `kloak` binary stays focused on the Kubernetes controller +
// webhook. `krunk` is intentionally a separate `main` package (not a
// kloak subcommand) so its dependency closure can shrink independently
// — e.g. it doesn't link in k8s.io/client-go.
//
// Today krunk exposes one subcommand:
//
//	krunk run --secrets <file> -- <cmd> [args...]
//
// More subcommands (validate, version) will land in follow-up PRs.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "krunk",
	Short: "Run a binary with kloak's in-kernel TLS rewrite (no Kubernetes)",
	Long: `krunk is kloak's host-CLI runtime. It launches a child process
inside a transient cgroup on the local host while kloak's eBPF programs
rewrite shadow placeholders to real secret values on outbound TLS.

No Kubernetes cluster, controller, or webhook is required.`,
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func main() {
	err := rootCmd.Execute()
	// runRun returns *exitCodeError for "child exited non-zero" so its
	// deferred cleanups can complete before we terminate the process.
	// Translate the sentinel to os.Exit here, after Execute (and all
	// of its defers, including runRun's) have returned. runCmd has
	// SilenceErrors set, so we print real errors ourselves below.
	var ec *exitCodeError
	if errors.As(err, &ec) {
		// Flush covcounters BEFORE os.Exit — os.Exit skips Go's
		// runtime exit hooks, so the standard `-cover` auto-flush
		// wouldn't fire. flushCoverage is a no-op in production
		// builds (compiled in only via `-tags cover`).
		flushCoverage()
		os.Exit(ec.code)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		flushCoverage()
		os.Exit(1)
	}
	flushCoverage()
}
