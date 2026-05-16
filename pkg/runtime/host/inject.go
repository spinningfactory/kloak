//go:build linux

package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// materializeInjection writes shadow placeholders to disk and / or
// composes a `KEY=value` env slice per the `Inject` directive on each
// Secret in the snapshot. Returns the env slice (to merge into
// cmd.Env) and a cleanup function that removes the per-invocation
// tmpfs subdir.
//
// Errors short-circuit and trigger an immediate cleanup of any files
// already written, so a half-applied injection doesn't leak a tmpfs
// subdir that a subsequent invocation could collide with.
//
// Cleanup is idempotent: callers may defer it on every exit path.
func materializeInjection(snap []secrets.Secret, dir string) (env []string, cleanup func() error, err error) {
	cleanup = func() error { return removeInjectDir(dir) }

	// If anything inside this function errors, run the cleanup before
	// returning so a partial write doesn't leak.
	defer func() {
		if err != nil {
			_ = cleanup()
		}
	}()

	dirCreated := false
	for i := range snap {
		s := &snap[i]
		if s.Inject.Env != "" {
			// The shadow placeholder is what the child should see;
			// the BPF map rewrites it on the wire to s.Real.
			env = append(env, s.Inject.Env+"="+s.Shadow)
		}
		if s.Inject.File != "" {
			if !dirCreated {
				if err = os.MkdirAll(dir, 0o700); err != nil {
					return nil, cleanup, fmt.Errorf("mkdir injection dir %s: %w", dir, err)
				}
				dirCreated = true
			}
			if err = writeInjectFile(dir, s); err != nil {
				return nil, cleanup, err
			}
		}
	}

	return env, cleanup, nil
}

// writeInjectFile drops a single secret's shadow placeholder at the
// requested filesystem path. The caller-provided `Inject.File` is an
// absolute path inside the child's view of the filesystem; we mirror
// the directory structure under `dir` so the runtime owns its own
// staging area (and so cleanup is a single RemoveAll).
//
// The child is expected to read the file at `Inject.File` directly —
// the staging path is unrelated. Bind-mounting the staging dir onto
// the child's filesystem is a follow-up; for now the file is created
// at its absolute path on the host, which works for the host-cgroup
// runtime where parent and child share a filesystem.
func writeInjectFile(stagingDir string, s *secrets.Secret) error {
	path := s.Inject.File
	if !filepath.IsAbs(path) {
		return fmt.Errorf("inject.file for secret %q must be absolute: %q", s.Key, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir parent of %s: %w", path, err)
	}
	// 0o400 — read-only for the owner. The child inherits the
	// runtime's uid today; a future PR will own the uid drop.
	if err := os.WriteFile(path, []byte(s.Shadow), 0o400); err != nil {
		return fmt.Errorf("write inject file %s: %w", path, err)
	}
	// Touch a sentinel inside the staging dir so cleanup knows the
	// runtime claimed this invocation. Useful when debugging leaked
	// dirs across crashes.
	sentinel := filepath.Join(stagingDir, "."+filepath.Base(path))
	if err := os.WriteFile(sentinel, []byte(path), 0o600); err != nil {
		// Sentinel failure is non-fatal — the real injection succeeded.
		_ = err
	}
	return nil
}

// removeInjectDir wipes the per-invocation staging dir. Files written
// to absolute `inject.file` paths outside the dir are NOT removed —
// they're the child's responsibility once the runtime hands them
// over, and a stale file outside the staging area is observable by
// the operator (vs. a hidden tmpfs leak).
//
// Idempotent.
func removeInjectDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("remove injection dir %s: %w", dir, err)
	}
	return nil
}
