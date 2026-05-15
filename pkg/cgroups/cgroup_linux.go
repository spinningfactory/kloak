//go:build linux

package cgroups

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// KloakSliceName is the directory under the cgroup root where every
// `kloak run` invocation creates its transient cgroup. The `.slice`
// suffix is a courtesy to systemd-managed hosts (so a top-level
// kloak.slice can be hand-delegated if needed); on a pure cgroup v2
// system it's just a regular directory.
const KloakSliceName = "kloak.slice"

// GetCgroupInodeFromPath returns the inode number of a cgroup directory on Linux.
func GetCgroupInodeFromPath(path string) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}

// CreateTransient mkdirs a fresh cgroup at <cgroupRoot>/<KloakSliceName>/<name>
// and returns its path, inode ID, and a cleanup function.
//
// The KloakSliceName parent is created on demand and is intentionally
// NOT removed by the cleanup function — multiple concurrent `kloak run`
// invocations share that parent, and Phase 4 will handle a startup
// sweep for orphans.
//
// `name` must be a non-empty single path component (no `/`, no `..`).
// Callers typically pass a UUID. We validate explicitly rather than
// leaning on filepath.Join's normalization so a malicious name fails
// loudly instead of escaping the slice parent.
//
// The cleanup function is idempotent: calling it after the cgroup is
// already gone returns nil. It only errors when the cgroup is
// non-empty (e.g. a child process is still alive in `cgroup.procs`) —
// at which point the runtime's signal handler is expected to have
// killed the survivors first.
//
// Errors from the initial mkdir (read-only cgroupfs, permission
// denied, …) are wrapped with the candidate path so the operator can
// fix the host without spelunking through syscall errors.
func CreateTransient(cgroupRoot, name string) (path string, id uint64, cleanup func() error, err error) {
	if cgroupRoot == "" {
		cgroupRoot = DefaultCgroupRoot
	}
	if err := validateTransientName(name); err != nil {
		return "", 0, nil, err
	}

	parent := filepath.Join(cgroupRoot, KloakSliceName)
	// MkdirAll is idempotent on an already-existing parent and a no-op
	// when permissions allow but the dir is already there. Permission
	// denied / read-only fs surfaces here for the operator.
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", 0, nil, fmt.Errorf("create kloak slice parent %s (cgroupfs writable?): %w", parent, err)
	}

	path = filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			// Same-name collision means a previous run leaked or two
			// concurrent callers picked the same name. Either way, this
			// invocation can't safely take ownership.
			return "", 0, nil, fmt.Errorf("transient cgroup %s already exists; pick a unique name", path)
		}
		return "", 0, nil, fmt.Errorf("create transient cgroup %s: %w", path, err)
	}

	id, statErr := GetCgroupInodeFromPath(path)
	if statErr != nil {
		// The mkdir succeeded but we can't stat — best effort: try to
		// remove what we just created so we don't leak a half-built
		// transient cgroup.
		_ = os.Remove(path)
		return "", 0, nil, fmt.Errorf("stat transient cgroup %s: %w", path, statErr)
	}

	cleanup = makeTransientCleanup(path)
	return path, id, cleanup, nil
}

// makeTransientCleanup returns a closure that removes path exactly
// once. Idempotent: subsequent calls return nil even if path is gone.
func makeTransientCleanup(path string) func() error {
	return func() error {
		if err := os.Remove(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("rmdir transient cgroup %s: %w", path, err)
		}
		return nil
	}
}

// validateTransientName rejects names that would let mkdir escape the
// kloak slice parent. We allow most printable chars (cgroup directory
// names are flexible) but disallow path-separator / parent-dir tricks.
func validateTransientName(name string) error {
	if name == "" {
		return errors.New("transient cgroup name must not be empty")
	}
	if strings.ContainsRune(name, '/') {
		return fmt.Errorf("transient cgroup name %q must not contain `/`", name)
	}
	if name == "." || name == ".." || strings.Contains(name, "..") {
		return fmt.Errorf("transient cgroup name %q must not contain `..` or `.`", name)
	}
	return nil
}
