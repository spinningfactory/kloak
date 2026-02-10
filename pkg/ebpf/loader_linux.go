//go:build linux

// Package ebpf provides eBPF program loading and management.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" redirect ../../pkg/ebpf/redirect.c -- -I../../pkg/ebpf
package ebpf

import (
	"errors"
	"fmt"
	"os"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// LinuxLoader is the Linux-specific loader with typed fields.
// This wraps the platform-agnostic Loader type.
type LinuxLoader struct {
	*Loader
	objs     *redirectObjects
	connect4 link.Link
	connect6 link.Link
}

// NewLinuxLoader creates a new eBPF loader for Linux.
func NewLinuxLoader(cgroupPath string) *LinuxLoader {
	return &LinuxLoader{
		Loader: NewLoader(cgroupPath),
	}
}

// Load loads and attaches the eBPF programs.
func (l *LinuxLoader) Load() error {
	// Load pre-compiled eBPF programs
	l.objs = &redirectObjects{}
	if err := loadRedirectObjects(l.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Open cgroup for attachment
	cgroup, err := os.Open(l.cgroupPath)
	if err != nil {
		return fmt.Errorf("opening cgroup %s: %w", l.cgroupPath, err)
	}
	defer cgroup.Close()

	// Attach connect4 hook
	l.connect4, err = link.AttachCgroup(link.CgroupOptions{
		Path:    l.cgroupPath,
		Attach:  ciliumebpf.AttachCGroupInet4Connect,
		Program: l.objs.CgroupConnect4,
	})
	if err != nil {
		return fmt.Errorf("attaching connect4: %w", err)
	}

	// Attach connect6 hook
	l.connect6, err = link.AttachCgroup(link.CgroupOptions{
		Path:    l.cgroupPath,
		Attach:  ciliumebpf.AttachCGroupInet6Connect,
		Program: l.objs.CgroupConnect6,
	})
	if err != nil {
		l.connect4.Close()
		return fmt.Errorf("attaching connect6: %w", err)
	}

	return nil
}

// AddCgroup adds a cgroup ID to be tracked for traffic redirection.
func (l *LinuxLoader) AddCgroup(cgroupID uint64) error {
	if l.objs == nil {
		return errors.New("eBPF not loaded")
	}
	enabled := uint8(1)
	return l.objs.TrackedCgroups.Put(cgroupID, enabled)
}

// RemoveCgroup removes a cgroup ID from tracking.
func (l *LinuxLoader) RemoveCgroup(cgroupID uint64) error {
	if l.objs == nil {
		return errors.New("eBPF not loaded")
	}
	return l.objs.TrackedCgroups.Delete(cgroupID)
}

// GetOriginalDst retrieves the original destination for a socket cookie.
func (l *LinuxLoader) GetOriginalDst(socketCookie uint64) (*OriginalDst, error) {
	if l.objs == nil {
		return nil, errors.New("eBPF not loaded")
	}
	var dst OriginalDst
	err := l.objs.OriginalDst.Lookup(socketCookie, &dst)
	if err != nil {
		return nil, err
	}
	return &dst, nil
}

// Close releases all eBPF resources.
func (l *LinuxLoader) Close() error {
	var errs []error

	if l.connect4 != nil {
		if err := l.connect4.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if l.connect6 != nil {
		if err := l.connect6.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if l.objs != nil {
		if err := l.objs.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("closing eBPF resources: %v", errs)
	}
	return nil
}
