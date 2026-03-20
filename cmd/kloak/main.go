package main

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kloak",
	Short: "Kloak - Kubernetes eBPF HTTPS Interceptor",
	Long: `Kloak transparently intercepts HTTPS traffic in Kubernetes pods,
rewrites hashed headers to original values, and enables secure
API key management without exposing secrets in plain text.`,
}

func init() {
	rootCmd.AddCommand(controllerCmd)
	rootCmd.AddCommand(webhookCmd)
	rootCmd.AddCommand(certGenCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
