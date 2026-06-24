package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// writeTempYAML writes body to a temp file with the given extension
// and returns its path. Cheap fixture pattern.
func writeTempYAML(t *testing.T, ext, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secrets"+ext)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

func TestOpenSecretsSource_YAMLValid(t *testing.T) {
	path := writeTempYAML(t, ".yaml", `secrets:
  - name: x
    value: src-snapshot-real
    inject:
      env: X
`)
	src, err := openSecretsSource(path)
	if err != nil {
		t.Fatalf("openSecretsSource: %v", err)
	}
	if src == nil {
		t.Fatal("nil Source")
	}
}

func TestOpenSecretsSource_YMLAndUppercase(t *testing.T) {
	// .yml and case-insensitive extensions both route to the YAML loader.
	for _, ext := range []string{".yml", ".YAML", ".YML"} {
		t.Run(ext, func(t *testing.T) {
			path := writeTempYAML(t, ext, `secrets:
  - name: x
    value: src-snapshot-real
    inject:
      env: X
`)
			if _, err := openSecretsSource(path); err != nil {
				t.Errorf("%s dispatch failed: %v", ext, err)
			}
		})
	}
}

func TestOpenSecretsSource_UnsupportedExtension(t *testing.T) {
	path := writeTempYAML(t, ".txt", "irrelevant")
	_, err := openSecretsSource(path)
	if err == nil {
		t.Fatal("expected error for .txt")
	}
	if !strings.Contains(err.Error(), `unsupported secrets file extension ".txt"`) {
		t.Errorf("error %q should mention the unsupported extension", err)
	}
	if !strings.Contains(err.Error(), ".yaml") || !strings.Contains(err.Error(), ".yml") {
		t.Errorf("error %q should advertise supported extensions", err)
	}
}

func TestOpenSecretsSource_ValidatorErrorPropagates(t *testing.T) {
	path := writeTempYAML(t, ".yaml", `secrets:
  - name: bad
    value: v
    port: not-a-port
    inject:
      env: X
`)
	_, err := openSecretsSource(path)
	if err == nil {
		t.Fatal("expected validator error")
	}
	if !strings.Contains(err.Error(), "invalid port") {
		t.Errorf("expected port error, got: %v", err)
	}
}

// newRunCmd builds an isolated copy of the run command with its
// streams redirected to a buffer. Avoids mutating the package-level
// runCmd across tests. The closure picks up runSecretsPath from the
// package-level vars set in run.go's flag bindings — we reset those
// in the per-test setup helper.
func newRunCmd(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	c := &cobra.Command{
		Use:  "run [flags] -- <cmd> [args...]",
		Args: cobra.MinimumNArgs(1),
		RunE: runRun,
	}
	c.Flags().StringVar(&runSecretsPath, "secrets", "", "")
	c.Flags().StringVar(&runCgroupRoot, "cgroup-root", "", "")
	c.Flags().StringVar(&runInjectRoot, "inject-root", "", "")
	c.SetOut(buf)
	c.SetErr(buf)
	c.SilenceUsage = true
	c.SilenceErrors = true
	c.SetContext(context.Background())
	// Reset flag-bound vars between tests so previous test state doesn't bleed.
	runSecretsPath = ""
	runCgroupRoot = ""
	runInjectRoot = ""
	return c, buf
}

func TestRunRun_MissingSecretsFlagRejected(t *testing.T) {
	cmd, _ := newRunCmd(t)
	cmd.SetArgs([]string{"echo", "hi"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --secrets is missing")
	}
	if !strings.Contains(err.Error(), "--secrets is required") {
		t.Errorf("expected `--secrets is required`, got: %v", err)
	}
}

func TestRunRun_UnsupportedExtension(t *testing.T) {
	bad := writeTempYAML(t, ".txt", "irrelevant")
	cmd, _ := newRunCmd(t)
	cmd.SetArgs([]string{"--secrets", bad, "--", "echo", "hi"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected dispatcher error")
	}
	if !strings.Contains(err.Error(), "unsupported secrets file extension") {
		t.Errorf("expected extension error, got: %v", err)
	}
}

func TestRunRun_MissingPositionalCmdRejected(t *testing.T) {
	// cobra.MinimumNArgs(1) rejects empty positional args. Belt-and-
	// suspenders on the args contract.
	good := writeTempYAML(t, ".yaml", `secrets:
  - name: x
    value: src-snapshot-real
    inject:
      env: X
`)
	cmd, _ := newRunCmd(t)
	cmd.SetArgs([]string{"--secrets", good})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for missing positional cmd")
	}
}
