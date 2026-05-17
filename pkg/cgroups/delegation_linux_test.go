//go:build linux

package cgroups

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractUserDelegatedPath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "systemd user session — service is the boundary",
			in:   "/user.slice/user-501.slice/user@501.service/app.slice/foo",
			want: "/user.slice/user-501.slice/user@501.service",
		},
		{
			name: "session.scope alone — no service segment, no delegation",
			in:   "/user.slice/user-501.slice/session-6.scope",
			want: "",
		},
		{
			name: "service is the leaf",
			in:   "/user.slice/user-1000.slice/user@1000.service",
			want: "/user.slice/user-1000.slice/user@1000.service",
		},
		{
			name: "system daemon — no user@ segment",
			in:   "/system.slice/foo.service",
			want: "",
		},
		{
			name: "kubepods — no user@ segment, return empty",
			in:   "/kubepods.slice/kubepods-besteffort.slice/pod-abc/cri-containerd-xyz.scope",
			want: "",
		},
		{
			name: "root cgroup",
			in:   "/",
			want: "",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
		{
			name: "lookalike but non-numeric uid is rejected",
			in:   "/user.slice/user-foo.slice/user@admin.service/app",
			want: "",
		},
		{
			name: "user@.service with no digits is rejected",
			in:   "/user.slice/user@.service/app",
			want: "",
		},
		{
			name: "high uid still matches",
			in:   "/user.slice/user-65534.slice/user@65534.service",
			want: "/user.slice/user-65534.slice/user@65534.service",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractUserDelegatedPath(c.in)
			if got != c.want {
				t.Errorf("extractUserDelegatedPath(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestIsUserAtService(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"user@0.service", true},
		{"user@501.service", true},
		{"user@1000.service", true},
		// reject lookalikes
		{"user@.service", false},
		{"user@root.service", false},
		{"user@501.service.bak", false},
		{"x-user@501.service", false},
		{"user@501", false},
		{"", false},
		{"session-6.scope", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := isUserAtService(c.in); got != c.want {
				t.Errorf("isUserAtService(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestDiscoverUserDelegatedRoot_Integration is best-effort: when this
// test runs as the logged-in user on a systemd host, the function
// should return a writable directory. We don't assert the exact path
// (depends on uid) — just that *some* writable delegated root exists
// AND we can mkdir under it.
//
// Skips on:
//   - root (uid 0): the discovery path is for non-root only; root has
//     /sys/fs/cgroup writable directly.
//   - CI / container runners: many CI envs run jobs under
//     system.slice/.../$JOB (no user.slice segment in /proc/self/cgroup).
func TestDiscoverUserDelegatedRoot_Integration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skip: root has /sys/fs/cgroup writable directly; delegation discovery is non-root")
	}
	root, err := DiscoverUserDelegatedRoot("")
	if err != nil {
		if errors.Is(err, ErrNoUserDelegation) {
			t.Skip("skip: no user-delegated cgroup found (likely CI runner or non-systemd host)")
		}
		t.Fatalf("DiscoverUserDelegatedRoot: %v", err)
	}
	// Probe: mkdir + rmdir a unique subdir. Confirms the path the
	// function returned is genuinely usable for kloak's CreateTransient,
	// not just stat-accessible.
	probe := filepath.Join(root, "kloak-delegation-probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		t.Errorf("mkdir under delegated root %s: %v", probe, err)
		return
	}
	if err := os.Remove(probe); err != nil {
		t.Errorf("rmdir probe %s: %v", probe, err)
	}
}

func TestReadSelfCgroupV2(t *testing.T) {
	// We can't stub /proc/self/cgroup easily, but on any modern Linux
	// distro it should at minimum return a v2 path. The integration
	// shape: the function returns a non-empty path starting with "/".
	got, err := readSelfCgroupV2()
	if errors.Is(err, ErrNoUserDelegation) {
		t.Skip("skip: kernel doesn't expose a cgroup v2 entry for this process")
	}
	if err != nil {
		t.Fatalf("readSelfCgroupV2: %v", err)
	}
	if got == "" {
		t.Errorf("expected non-empty cgroup path, got empty")
	}
	if got[0] != '/' {
		t.Errorf("expected absolute path, got %q", got)
	}
}
