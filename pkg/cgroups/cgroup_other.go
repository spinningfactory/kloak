//go:build !linux

package cgroups

import (
	"fmt"
)

// KloakSliceName is exported on every OS so callers can reference the
// constant in shared code; only the Linux implementation actually
// creates the directory.
const KloakSliceName = "kloak.slice"

// GetCgroupInodeFromPath returns a placeholder inode on non-Linux systems.
func GetCgroupInodeFromPath(_ string) (uint64, error) {
	return 0, fmt.Errorf("cgroups not supported on this OS")
}

// CreateTransient is a non-Linux stub. Mirrors uprobe_other.go's
// pattern from PR #217: signature matches the real implementation so
// the rest of the codebase compiles on macOS for unit testing, and
// every method returns an actionable "not supported" error.
func CreateTransient(_, _ string) (string, uint64, func() error, error) {
	return "", 0, nil, fmt.Errorf("cgroups not supported on this OS")
}
