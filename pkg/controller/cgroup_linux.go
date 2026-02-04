//go:build linux

package controller

import (
	"os"
	"syscall"
)

// getCgroupInodeFromPath returns the inode number of a cgroup directory on Linux.
func getCgroupInodeFromPath(path string, _ os.FileInfo) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}
