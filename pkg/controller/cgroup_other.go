//go:build !linux

package controller

import (
	"errors"
	"os"
)

// getCgroupInodeFromPath is a stub for non-Linux platforms.
func getCgroupInodeFromPath(_ string, _ os.FileInfo) (uint64, error) {
	return 0, errors.New("cgroup inode lookup only supported on Linux")
}
