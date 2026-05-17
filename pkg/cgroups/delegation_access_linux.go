//go:build linux

package cgroups

import "golang.org/x/sys/unix"

// syscallAccess wraps unix.Access. Separated into its own file so the
// non-Linux build (which can't import sys/unix's Linux-only constants)
// doesn't need to deal with it.
func syscallAccess(path string, mode uint32) error {
	return unix.Access(path, mode)
}
