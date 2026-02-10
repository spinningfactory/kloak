//go:build linux

package ebpf

import (
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
)

// EBPFCgroupManager wraps the eBPF loader to implement the CgroupManager interface.
type EBPFCgroupManager struct {
	loader *LinuxLoader
}

// NewEBPFCgroupManager creates a new eBPF-backed cgroup manager.
func NewEBPFCgroupManager(cgroupPath string) (*EBPFCgroupManager, error) {
	log := ctrl.Log.WithName("ebpf")
	log.Info("Initializing eBPF loader", "cgroupPath", cgroupPath)

	loader := NewLinuxLoader(cgroupPath)
	if err := loader.Load(); err != nil {
		return nil, fmt.Errorf("loading eBPF programs: %w", err)
	}

	log.Info("eBPF programs loaded and attached")
	return &EBPFCgroupManager{loader: loader}, nil
}

// AddCgroup adds a cgroup ID to the eBPF map for traffic redirection.
func (m *EBPFCgroupManager) AddCgroup(cgroupID uint64) error {
	ctrl.Log.Info("Adding cgroup to eBPF map", "cgroupID", cgroupID)
	return m.loader.AddCgroup(cgroupID)
}

// RemoveCgroup removes a cgroup ID from the eBPF map.
func (m *EBPFCgroupManager) RemoveCgroup(cgroupID uint64) error {
	ctrl.Log.Info("Removing cgroup from eBPF map", "cgroupID", cgroupID)
	return m.loader.RemoveCgroup(cgroupID)
}

// Close releases all eBPF resources.
func (m *EBPFCgroupManager) Close() error {
	return m.loader.Close()
}
