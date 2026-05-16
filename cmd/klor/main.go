// Command klor is kloak's host-CLI runtime. It wraps a child process
// in a transient cgroup with kloak's eBPF data plane active so the
// child's shadow placeholders get rewritten to real values on outbound
// TLS — same end state as a kloak-enabled Pod, no Kubernetes needed.
//
// The `kloak` binary stays focused on the Kubernetes controller +
// webhook. `klor` is intentionally a separate `main` package (not a
// kloak subcommand) so its dependency closure can shrink independently
// — e.g. it doesn't link in k8s.io/client-go.
//
// Today klor exposes one subcommand:
//
//	klor run --secrets <file> -- <cmd> [args...]
//
// More subcommands (validate, version) will land in follow-up PRs.
package main

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "klor",
	Short: "Run a binary with kloak's in-kernel TLS rewrite (no Kubernetes)",
	Long: `klor is kloak's host-CLI runtime. It launches a child process
inside a transient cgroup on the local host while kloak's eBPF programs
rewrite shadow placeholders to real secret values on outbound TLS.

No Kubernetes cluster, controller, or webhook is required.`,
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
