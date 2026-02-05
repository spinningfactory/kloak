package main

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "bouncer",
	Short: "Bouncer - Kubernetes eBPF HTTPS Interceptor",
	Long: `Bouncer transparently intercepts HTTPS traffic in Kubernetes pods,
rewrites hashed headers to original values, and enables secure
API key management without exposing secrets in plain text.`,
}

func init() {
	rootCmd.AddCommand(controllerCmd)
	rootCmd.AddCommand(webhookCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
