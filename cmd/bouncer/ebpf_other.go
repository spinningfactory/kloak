//go:build !linux

package main

import "errors"

// EBPFCgroupManager is a stub for non-Linux platforms.
type EBPFCgroupManager struct{}

// NewEBPFCgroupManager returns an error on non-Linux platforms.
func NewEBPFCgroupManager(cgroupPath string) (*EBPFCgroupManager, error) {
	return nil, errors.New("eBPF is only supported on Linux")
}

func (m *EBPFCgroupManager) AddCgroup(cgroupID uint64) error    { return nil }
func (m *EBPFCgroupManager) RemoveCgroup(cgroupID uint64) error { return nil }
func (m *EBPFCgroupManager) Close() error                       { return nil }
