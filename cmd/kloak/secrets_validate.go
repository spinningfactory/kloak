package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Inspect and validate kloak secrets configuration",
	Long: `Subcommands for working with kloak secrets files. Today only
` + "`kloak secrets validate`" + ` is exposed; future subcommands will cover
templating and live inspection.`,
}

var secretsValidateCmd = &cobra.Command{
	Use:   "validate <path>",
	Short: "Validate a kloak secrets file",
	Long: `Loads a kloak secrets file, parses it, runs every validator that
the runtime would run, and prints a short summary on success. Exits non-zero
on any error so it can drop into CI.

The file format is selected by extension: .yaml/.yml use the YAML loader.
Future formats (.env, host-env, secret backends) will register through the
same dispatcher.`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		path := args[0]
		src, err := openSecretsSource(path)
		if err != nil {
			return err
		}
		snap, err := src.Snapshot(context.Background())
		if err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stdout, "%s: ok (%d secret%s)\n", path, len(snap), plural(len(snap))); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		for i := range snap {
			s := &snap[i]
			if _, err := fmt.Fprintf(os.Stdout, "  - %s: host=%q port=%d inject=%s\n",
				s.Key, hostOrIP(s), s.Port, formatInject(s.Inject)); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
		}
		return nil
	},
}

func init() {
	secretsCmd.AddCommand(secretsValidateCmd)
	rootCmd.AddCommand(secretsCmd)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// hostOrIP returns the textual host/IP form for the validator output.
// Host takes precedence; IP fills in for literal-IP secrets. Empty
// string when both are unset (wildcard). Takes a pointer to avoid the
// 144-byte hugeParam copy the linter flags.
func hostOrIP(s *secrets.Secret) string {
	if s.Host != "" {
		return s.Host
	}
	if s.IP != nil {
		return s.IP.String()
	}
	return ""
}

// formatInject renders the Inject targets compactly for `secrets validate`
// output. "env=NAME", "file=PATH", or "env=NAME,file=PATH"; "none" when
// both are empty (which the translator already rejects — printing "none"
// is just a defensive fallback).
func formatInject(in secrets.Inject) string {
	var parts []string
	if in.Env != "" {
		parts = append(parts, "env="+in.Env)
	}
	if in.File != "" {
		parts = append(parts, "file="+in.File)
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}
