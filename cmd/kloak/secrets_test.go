package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempYAML writes body to a temp file with the given extension and
// returns its path. Cheap fixture for the dispatcher tests below.
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
		t.Fatalf("unexpected error: %v", err)
	}
	if src == nil {
		t.Fatal("expected non-nil Source")
	}
}

func TestOpenSecretsSource_YMLExtensionAlsoWorks(t *testing.T) {
	// .yml and .yaml should both dispatch to the YAML loader so users
	// who prefer one or the other don't get a surprising error.
	path := writeTempYAML(t, ".yml", `secrets:
  - name: x
    value: src-snapshot-real
    inject:
      env: X
`)
	if _, err := openSecretsSource(path); err != nil {
		t.Errorf(".yml dispatch failed: %v", err)
	}
}

func TestOpenSecretsSource_UppercaseExtension(t *testing.T) {
	// Extension matching is case-insensitive (filepath.Ext + strings.ToLower).
	path := writeTempYAML(t, ".YAML", `secrets:
  - name: x
    value: src-snapshot-real
    inject:
      env: X
`)
	if _, err := openSecretsSource(path); err != nil {
		t.Errorf("uppercase .YAML should dispatch: %v", err)
	}
}

func TestOpenSecretsSource_UnsupportedExtension(t *testing.T) {
	path := writeTempYAML(t, ".txt", "irrelevant body")
	_, err := openSecretsSource(path)
	if err == nil {
		t.Fatal("expected error for .txt")
	}
	if !strings.Contains(err.Error(), `unsupported secrets file extension ".txt"`) {
		t.Errorf("error %q should mention the unsupported extension", err)
	}
	// The error must list supported extensions so the user knows what
	// to fix without reading source code.
	if !strings.Contains(err.Error(), ".yaml") || !strings.Contains(err.Error(), ".yml") {
		t.Errorf("error %q should advertise supported extensions", err)
	}
}

func TestOpenSecretsSource_PropagatesYAMLErrors(t *testing.T) {
	// Validator failures from the YAML loader must reach the caller
	// unwrapped (the dispatcher is a pass-through).
	path := writeTempYAML(t, ".yaml", `secrets:
  - name: bad
    value: src-snapshot-real
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
