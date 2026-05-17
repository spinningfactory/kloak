// Package runtime is the boundary between kloak's CLI
// (cmd/kloak/run.go) and the machinery that actually exposes shadow
// placeholders to a child process and intercepts its TLS writes.
//
// Concrete implementations:
//
//	pkg/runtime/host    Linux host-cgroup runtime. The child runs
//	                    as a normal host process inside a transient
//	                    cgroup, with kloak's eBPF programs loaded
//	                    into the host kernel. Requires CAP_SYS_ADMIN.
//	pkg/runtime/microvm libkrun-managed Linux microVM (planned).
//	                    The only path on macOS; opt-in stronger
//	                    isolation on Linux.
//
// Each Runtime owns its own end-to-end lifecycle:
//   - provision the isolation boundary (cgroup or VM)
//   - materialize injection per `Secret.Inject` (env vars / files)
//   - construct the eBPF data plane and program its secret_map from
//     the supplied secrets.Source
//   - fork+exec the child inside the boundary
//   - pump stdio and forward signals
//   - propagate exit code
//   - tear everything down
//
// The CLI sees only `Run(ctx, spec)`.
package runtime

import (
	"context"
	"io"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// Runtime is the surface every backend implements. Keep it minimal —
// the CLI's job is to construct a Spec and dispatch; everything
// backend-specific lives inside the implementation.
//
// Spec is passed by pointer because the struct is ~128 bytes today and
// growing; backends MUST treat it as read-only.
type Runtime interface {
	// Run blocks until the child process exits or ctx is cancelled.
	// Returns the child's exit code (>= 0) on a normal exit, or a
	// non-nil error if the runtime itself failed (provisioning,
	// attach, exec). A nil error with exitCode > 0 means the child
	// ran but returned a non-zero status — the CLI should mirror it.
	Run(ctx context.Context, spec *Spec) (exitCode int, err error)
}

// Spec is the input every Runtime accepts. Fields are deliberately
// flat — runtimes ignore what they don't use rather than asking the
// caller to construct backend-specific request types.
type Spec struct {
	// Cmd is the program to execute. Cmd[0] is the binary path
	// (looked up via PATH if no slash); the rest are argv.
	Cmd []string

	// ExtraEnv is appended to the inherited host environment. The
	// Runtime additionally injects `Secret.Inject.Env` placeholders
	// on top of these — `inject.env` values override matching keys
	// from ExtraEnv so the YAML config wins over the caller's
	// environment.
	ExtraEnv []string

	// WorkDir is the child's working directory. Empty inherits the
	// CLI process's cwd at the time of Run.
	WorkDir string

	// Secrets supplies the snapshot the runtime programs into the
	// BPF map. The runtime reads each Secret's `Inject` field to
	// decide how to surface the shadow placeholder to the child.
	// A nil Secrets means "no secrets to rewrite" — the runtime
	// still runs the child, just without TLS interception.
	Secrets secrets.Source

	// Stdin / Stdout / Stderr default to inheriting the parent
	// process's streams when these are nil. Tests inject buffers.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}
