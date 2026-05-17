//go:build linux

package cgroups

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrNoUserDelegation is returned when the current task is not running
// inside a systemd-style per-user cgroup-v2 delegated subtree. Callers
// distinguish this from real I/O errors so they can fall back to a
// privileged code path (`sudo`) with a clear remediation instead of
// retrying.
var ErrNoUserDelegation = errors.New("no user-delegated cgroup v2 subtree found")

// DiscoverUserDelegatedRoot returns the absolute path of the highest
// cgroup v2 directory under which the current (unprivileged) task is
// authorized to mkdir. On every systemd-managed host this is the
// `user@$UID.service` directory inside `/user.slice/user-$UID.slice/`,
// which systemd-logind delegates to the logged-in user at session
// start.
//
// Why this exists: cgroup mkdirs under the root `/sys/fs/cgroup`
// require CAP_SYS_ADMIN, which forces `klor` to run under `sudo`
// today. Routing kloak's transient cgroups through the user's
// delegated subtree drops that requirement entirely while keeping
// the same cgroup-v2 semantics (and the same `bpf_get_current_cgroup_id()`
// matching for the BPF data plane).
//
// DiscoverUserDelegatedRoot succeeds only when the caller is *already*
// inside a `user@$UID.service` subtree — the one layout where cgroup-v2
// process migration works without privilege escalation.
//
// Tempting (and previously implemented) was a "construct" fallback: when
// `/proc/self/cgroup` shows we're in `session-N.scope` (the common
// interactive-shell layout), `user@$UID.service` is a *sibling* under
// `user-$UID.slice` and is writable to the user. The directory mkdirs
// fine. The trap is the cgroup-v2 process-migration rule: writing a PID
// into the new cgroup's `cgroup.procs` additionally requires write
// access to the **common ancestor**'s `cgroup.procs`. The common ancestor
// of `session-N.scope` and `user@$UID.service` is `user-$UID.slice` —
// owned by root, no user write — so migration always fails with EPERM
// even though every other layer looked permissive.
//
// Callers that hit ErrNoUserDelegation from session.scope have two
// rootless options for the cgroup half:
//   - `systemd-run --user --scope -- klor run …` (re-launches klor inside
//     `user@$UID.service`; logind brokers the migration via dbus, with
//     its own root privilege)
//   - `sudo setcap cap_sys_admin+ep ./bin/klor` (file capability bypasses
//     the migration check entirely)
//
// And of course `sudo klor …` still works.
//
// `cgroupFsRoot` is normally "" (defaults to `/sys/fs/cgroup`); tests
// pass a temp directory.
func DiscoverUserDelegatedRoot(cgroupFsRoot string) (string, error) {
	if cgroupFsRoot == "" {
		cgroupFsRoot = DefaultCgroupRoot
	}
	rel, err := readSelfCgroupV2()
	if err != nil {
		return "", err
	}
	delegated := extractUserDelegatedPath(rel)
	if delegated == "" {
		return "", ErrNoUserDelegation
	}
	full := cgroupFsRoot + delegated
	if err := checkWritable(full); err != nil {
		return "", fmt.Errorf("%w: %s not writable to current user: %v", ErrNoUserDelegation, full, err)
	}
	return full, nil
}

// readSelfCgroupV2 returns the path component of the cgroup v2 entry
// from /proc/self/cgroup. Cgroup v2 entries are formatted as
// `0::/<relative-path>` (subsystem id 0, no controllers list). Returns
// ErrNoUserDelegation when no v2 line is present.
func readSelfCgroupV2() (string, error) {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Errorf("read /proc/self/cgroup: %w", err)
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		// v2 entries: `0::/path`. v1 entries: `N:controller:/path`.
		if rest, ok := strings.CutPrefix(s.Text(), "0::"); ok {
			return rest, nil
		}
	}
	if err := s.Err(); err != nil {
		return "", fmt.Errorf("scan /proc/self/cgroup: %w", err)
	}
	return "", ErrNoUserDelegation
}

// extractUserDelegatedPath walks the segments of a cgroup v2 path and
// returns the prefix up to and including the first `user@<digits>.service`
// segment, or "" if none is present. The returned path is rooted (starts
// with `/`) so it can be concatenated to the cgroupfs mount point
// directly.
//
// Examples:
//
//	/user.slice/user-501.slice/session-6.scope
//	→ /user.slice/user-501.slice (no user@.service, returns "")
//
//	/user.slice/user-501.slice/user@501.service/app.slice/foo
//	→ /user.slice/user-501.slice/user@501.service
//
// We pick the user@.service segment specifically (rather than the
// session scope) because systemd-logind grants Delegate=yes on the
// service but not on the scope — mkdirs only succeed at the service
// level and below.
func extractUserDelegatedPath(cgroupPath string) string {
	segs := strings.Split(cgroupPath, "/")
	var acc []string
	for _, seg := range segs {
		acc = append(acc, seg)
		if isUserAtService(seg) {
			return strings.Join(acc, "/")
		}
	}
	return ""
}

// isUserAtService reports whether a path segment matches the
// `user@<digits>.service` pattern. We accept any uid digits rather than
// the caller's uid because setuid binaries (uncommon for klor today,
// but worth not foreclosing) may legitimately run under a different
// effective uid than the cgroup was set up for. The writability probe
// in DiscoverUserDelegatedRoot is the real gate.
func isUserAtService(seg string) bool {
	const prefix = "user@"
	const suffix = ".service"
	if !strings.HasPrefix(seg, prefix) || !strings.HasSuffix(seg, suffix) {
		return false
	}
	digits := seg[len(prefix) : len(seg)-len(suffix)]
	if digits == "" {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// checkWritable confirms the directory exists and is writable by the
// current process. We do a real access(W_OK) syscall rather than just
// stat'ing — file mode bits and POSIX ACLs disagree, and only access()
// reflects the kernel's actual decision for mkdir.
func checkWritable(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	const W_OK = 2
	return syscallAccess(dir, W_OK)
}
