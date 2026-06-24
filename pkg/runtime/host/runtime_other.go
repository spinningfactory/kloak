//go:build !linux

// Non-Linux stub for the host runtime. The real implementation in
// runtime.go requires cgroups v2 and the linux-only signal forwarding
// path; macOS / Windows builds fall through to this stub so `go build
// ./...` stays clean.
//
// Callers (cmd/kloak/run.go) receive a Runtime whose Run() returns
// ErrNotSupported on every invocation — friendlier than a build-time
// failure and matches the pattern from PR #217's
// pkg/ebpf/uprobe_other.go.

package host

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"github.com/spinningfactory/kloak/pkg/runtime"
)

// ErrNotSupported is returned by every method of the non-Linux stub.
// Exported so the CLI can `errors.Is` against it for cleaner error
// messaging on macOS dev machines.
var ErrNotSupported = errors.New("kloak: host-cgroup runtime is only supported on Linux")

// Option mirrors the linux build's option type so callers compile
// identically on macOS / Windows. Options have no effect on the stub.
type Option func()

// WithEBPF is a no-op on the stub but exported so cmd/krunk compiles
// for cross-platform development. The stub's Run still returns
// ErrNotSupported regardless of options passed.
func WithEBPF() Option { return func() {} }

// New returns a stub Runtime on non-Linux. Signature matches the real
// linux implementation so callers compile identically; Run() errors.
func New(_, _ string, _ *zap.SugaredLogger, _ ...Option) runtime.Runtime {
	return &stubRuntime{}
}

type stubRuntime struct{}

func (*stubRuntime) Run(_ context.Context, _ *runtime.Spec) (int, error) {
	return -1, ErrNotSupported
}
