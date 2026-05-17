package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/spinningfactory/kloak/pkg/runtime"
	"github.com/spinningfactory/kloak/pkg/runtime/host"
	"github.com/spinningfactory/kloak/pkg/secrets"
	yamlsrc "github.com/spinningfactory/kloak/pkg/secrets/yaml"
)

var (
	runSecretsPath string
	runCgroupRoot  string
	runInjectRoot  string
)

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <cmd> [args...]",
	Short: "Run a binary with kloak's in-kernel TLS rewrite active",
	Long: `Run a binary under kloak's eBPF data plane on the local host. The
child sees shadow placeholders for every secret declared in ` + "`--secrets`" + `;
the kernel rewrites them to their real values on outbound TLS that
matches each secret's host / port filter.

The child runs in a transient cgroup created under
/sys/fs/cgroup/kloak.slice/ and is torn down on exit. Requires
CAP_SYS_ADMIN (or root) for cgroup + BPF program loading — same
operational profile as kloak's controller DaemonSet.

Example:

  sudo klor run --secrets ./secrets.yaml -- \
      curl -sk -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com/...

Use "--" to separate klor flags from the command to execute. The
command's exit code is propagated as klor's exit code.`,
	Args:          cobra.MinimumNArgs(1),
	RunE:          runRun,
	SilenceErrors: true, // exitCodeError's message is internal-only; never print.
	SilenceUsage:  true, // child exit codes shouldn't trigger cobra's usage dump.
}

func init() {
	runCmd.Flags().StringVar(&runSecretsPath, "secrets", "",
		"Path to a kloak secrets file (.yaml/.yml). Required.")
	runCmd.Flags().StringVar(&runCgroupRoot, "cgroup-root", "",
		"Cgroup v2 root (default: /sys/fs/cgroup). Override for tests or non-standard hosts.")
	runCmd.Flags().StringVar(&runInjectRoot, "inject-root", "",
		"Base directory for staging `inject.file` materializations (default: /run/kloak). Per-invocation subdir is created here and removed on exit.")
}

// runRun is the cobra RunE for `klor run`, extracted so tests can
// invoke the command logic directly with a *cobra.Command whose
// streams are redirected.
func runRun(cmd *cobra.Command, args []string) error {
	if runSecretsPath == "" {
		return errors.New("--secrets is required")
	}

	src, err := openSecretsSource(runSecretsPath)
	if err != nil {
		return err
	}

	logCfg := zap.NewProductionConfig()
	logCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	logger, err := logCfg.Build()
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()

	rt := host.New(runCgroupRoot, runInjectRoot, logger.Sugar())

	spec := &runtime.Spec{
		Cmd:     args,
		Secrets: src,
		Stdin:   cmd.InOrStdin(),
		Stdout:  cmd.OutOrStdout(),
		Stderr:  cmd.ErrOrStderr(),
	}

	exitCode, err := rt.Run(cmd.Context(), spec)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		// Mirror the child's status as klor's own exit code. We can't
		// call os.Exit here because that would skip the deferred
		// logger.Sync (and any future defers added to runRun). Return
		// a sentinel error type and let main translate it after
		// rootCmd.Execute returns, so all defers complete first.
		return &exitCodeError{code: exitCode}
	}
	return nil
}

// exitCodeError carries a child process's non-zero exit code from
// runRun back to main. It is NOT a real error — we use Go's error
// channel only because cobra's RunE expects one. main checks for
// this type and calls os.Exit AFTER all of runRun's defers complete.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("child exited %d", e.code) }

// openSecretsSource selects a secrets.Source implementation based on
// the file's extension. Inlined here (instead of imported from a
// shared package) because the dispatcher is 8 lines and adding a
// shared internal package for that surface today would be premature;
// when a third caller arrives we'll extract.
func openSecretsSource(path string) (secrets.Source, error) {
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".yaml", ".yml":
		return yamlsrc.NewSource(path)
	default:
		return nil, fmt.Errorf("unsupported secrets file extension %q (supported: .yaml, .yml)", ext)
	}
}
