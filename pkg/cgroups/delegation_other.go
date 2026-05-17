//go:build !linux

package cgroups

import "errors"

// ErrNoUserDelegation mirrors the linux-build sentinel so callers
// compile against the same error variable cross-platform.
var ErrNoUserDelegation = errors.New("no user-delegated cgroup v2 subtree found")

// DiscoverUserDelegatedRoot is a stub on non-Linux. Cgroup v2 is a
// Linux-only construct; macOS / Windows builds always fall back to the
// caller's privileged code path.
func DiscoverUserDelegatedRoot(_ string) (string, error) {
	return "", ErrNoUserDelegation
}
