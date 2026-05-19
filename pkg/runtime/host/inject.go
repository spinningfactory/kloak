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
// cmd.Env) and a cleanup function that removes every file the runtime
// wrote, including those at user-supplied absolute paths outside the
// staging dir.
//
// Errors short-circuit and trigger an immediate cleanup of any files
// already written, so a half-applied injection doesn't leak a tmpfs
// subdir that a subsequent invocation could collide with.
//
// Cleanup is idempotent: callers may defer it on every exit path.
//
// TODO(phase-3b-followup): when concurrent krunk invocations both
// declare the same `inject.file` path, the second one will fail at
// writeInjectFile (or worse, race the cleanup of the first). The
// libkrun backend solves this via virtio-fs into the guest; the host
// runtime will solve it by bind-mounting a per-invocation staging
// dir onto the absolute path. Until then, document the constraint:
// each `inject.file` path must be unique across concurrent invocations.
func materializeInjection(snap []secrets.Secret, dir string) (env []string, cleanup func() error, err error) {
	// Track every absolute path we write so cleanup can reverse the
	// whole materialization, not just the staging dir. The closure
	// captures `injectedPaths` by reference so later writes inside
	// this function show up at cleanup time too.
	var injectedPaths []string
	cleanup = func() error { return removeInjection(injectedPaths, dir) }

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
				if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
					err = mkErr // trip the deferred cleanup-on-error
					return nil, cleanup, fmt.Errorf("mkdir injection dir %s: %w", dir, mkErr)
				}
				dirCreated = true
			}
			if wErr := writeInjectFile(dir, s); wErr != nil {
				err = wErr // trip the deferred cleanup-on-error
				return nil, cleanup, wErr
			}
			injectedPaths = append(injectedPaths, s.Inject.File)
		}
	}

	return env, cleanup, nil
}

// writeInjectFile drops a single secret's shadow placeholder at the
// caller-provided `Inject.File` path. The path must be absolute — the
// child reads it directly from its (shared-with-parent) view of the
// filesystem. The staging dir is used only for a per-invocation
// sentinel that records the absolute path; it helps postmortem
// debugging when the parent crashes mid-run and leaves both the
// sentinel and the real file behind.
//
// Future work (bind-mount-based isolation): the staging dir will hold
// the real file and a virtio-fs / bind-mount will project it at the
// child's absolute path. Until then, parent and child share the
// filesystem and the absolute path IS the storage location.
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
	// Touch a sentinel inside the staging dir so postmortem tools can
	// correlate stale absolute-path files with the invocation that
	// wrote them. Non-fatal if it fails — the real injection succeeded.
	sentinel := filepath.Join(stagingDir, "."+filepath.Base(path))
	_ = os.WriteFile(sentinel, []byte(path), 0o600)
	return nil
}

// removeInjection wipes every file the runtime wrote: each
// user-supplied `Inject.File` absolute path AND the per-invocation
// staging dir (which holds the sentinels). Failures are joined into
// a single error so cleanup never short-circuits on a partial removal.
//
// Idempotent — missing entries are treated as success, since the
// runtime's defer chain may invoke cleanup more than once on
// error paths.
func removeInjection(injectedPaths []string, stagingDir string) error {
	var errs []error
	for _, p := range injectedPaths {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove inject file %s: %w", p, err))
		}
	}
	if err := os.RemoveAll(stagingDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove injection staging dir %s: %w", stagingDir, err))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
