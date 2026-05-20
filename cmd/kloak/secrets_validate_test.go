package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// newValidateCmd builds an isolated copy of the validate command for a
// test. Using the package-level secretsValidateCmd directly would let
// state leak between tests (output buffers, args) — and Cobra's docs
// warn against reusing commands across runs in tests. Cloning ensures
// each test gets a fresh RunE binding to runSecretsValidate.
func newValidateCmd(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	cmd := &cobra.Command{
		Use:  "validate <path>",
		Args: cobra.ExactArgs(1),
		RunE: runSecretsValidate,
	}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	// SilenceUsage so cobra's auto-printed usage block doesn't
	// contaminate the output buffer when we're asserting on it.
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetContext(context.Background())
	return cmd, buf
}

func TestRunSecretsValidate_HappyPath(t *testing.T) {
	t.Setenv("KLOAK_TEST_REAL", "from-env-real")
	path := writeTempYAML(t, ".yaml", `secrets:
  - name: stripe-key
    value: sk-live-abcdef
    host: api.stripe.com
    port: 443
    inject:
      env: STRIPE_KEY
  - name: openai
    valueFrom:
      env: KLOAK_TEST_REAL
    inject:
      env: OPENAI_KEY
      file: /run/kloak/openai
`)
	cmd, buf := newValidateCmd(t)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	// Summary line counts both entries.
	if !strings.Contains(out, "ok (2 secrets)") {
		t.Errorf("missing 2-secret summary in output:\n%s", out)
	}
	// Per-entry lines surface host + inject metadata.
	if !strings.Contains(out, `stripe-key: host="api.stripe.com" port=443 inject=env=STRIPE_KEY`) {
		t.Errorf("stripe-key line missing or wrong:\n%s", out)
	}
	if !strings.Contains(out, `openai: host="" port=0 inject=env=OPENAI_KEY,file=/run/kloak/openai`) {
		t.Errorf("openai line missing or wrong:\n%s", out)
	}
}

func TestRunSecretsValidate_SingleSecretPluralForm(t *testing.T) {
	// One secret → "(1 secret)" not "(1 secrets)". Guards the plural helper.
	path := writeTempYAML(t, ".yaml", `secrets:
  - name: only
    value: src-snapshot-real
    inject:
      env: ONLY
`)
	cmd, buf := newValidateCmd(t)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "ok (1 secret)") {
		t.Errorf("expected singular `1 secret`, got:\n%s", buf.String())
	}
}

func TestRunSecretsValidate_ValidatorErrorPropagates(t *testing.T) {
	path := writeTempYAML(t, ".yaml", `secrets:
  - name: bad
    value: src-snapshot-real
    port: not-a-port
    inject:
      env: X
`)
	cmd, _ := newValidateCmd(t)
	cmd.SetArgs([]string{path})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected validator error")
	}
	if !strings.Contains(err.Error(), "invalid port") {
		t.Errorf("expected port error, got: %v", err)
	}
}

func TestRunSecretsValidate_UnsupportedExtension(t *testing.T) {
	path := writeTempYAML(t, ".txt", "irrelevant")
	cmd, _ := newValidateCmd(t)
	cmd.SetArgs([]string{path})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected dispatcher error")
	}
	if !strings.Contains(err.Error(), "unsupported secrets file extension") {
		t.Errorf("expected extension error, got: %v", err)
	}
}

func TestRunSecretsValidate_MissingArgsRejected(t *testing.T) {
	// cobra.ExactArgs(1) rejects zero or multiple args. Belt-and-suspenders
	// on the args contract.
	cmd, _ := newValidateCmd(t)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for missing args")
	}
}

func TestHostOrIP(t *testing.T) {
	cases := []struct {
		name string
		s    secrets.Secret
		want string
	}{
		{"host wins", secrets.Secret{Host: "api.stripe.com"}, "api.stripe.com"},
		{"host takes precedence over IP", secrets.Secret{Host: "api.stripe.com", IP: net.ParseIP("192.0.2.1")}, "api.stripe.com"},
		{"IP fallback", secrets.Secret{IP: net.ParseIP("192.0.2.1")}, "192.0.2.1"},
		{"empty wildcard", secrets.Secret{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.s
			if got := hostOrIP(&s); got != tc.want {
				t.Errorf("hostOrIP(%+v) = %q, want %q", tc.s, got, tc.want)
			}
		})
	}
}

func TestFormatInject(t *testing.T) {
	cases := []struct {
		name string
		in   secrets.Inject
		want string
	}{
		{"env only", secrets.Inject{Env: "STRIPE_KEY"}, "env=STRIPE_KEY"},
		{"file only", secrets.Inject{File: "/run/kloak/x"}, "file=/run/kloak/x"},
		{"both", secrets.Inject{Env: "E", File: "/f"}, "env=E,file=/f"},
		{"none (defensive)", secrets.Inject{}, "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatInject(tc.in); got != tc.want {
				t.Errorf("formatInject(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPlural(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want string
	}{
		{0, "s"}, {1, ""}, {2, "s"}, {100, "s"},
	} {
		if got := plural(tc.n); got != tc.want {
			t.Errorf("plural(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
