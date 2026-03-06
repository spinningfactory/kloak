//go:build !linux

package cgroups

import (
	"fmt"
)

// GetCgroupInodeFromPath returns a placeholder inode on non-Linux systems.
func GetCgroupInodeFromPath(path string) (uint64, error) {
	return 0, fmt.Errorf("cgroups not supported on this OS")
}
