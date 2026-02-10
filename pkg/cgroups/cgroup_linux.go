//go:build linux

package cgroups

import (
	"syscall"
)

// GetCgroupInodeFromPath returns the inode number of a cgroup directory on Linux.
func GetCgroupInodeFromPath(path string) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}
