// Package ebpf provides eBPF program loading and management.
package ebpf

// Loader is the base loader type with platform-agnostic fields.
// On Linux, use NewLinuxLoader() to get a fully functional loader.
// On other platforms, this provides the structure but methods won't work.
type Loader struct {
	cgroupPath string
}

// NewLoader creates a new base loader.
// On Linux, prefer NewLinuxLoader() for a fully functional loader.
func NewLoader(cgroupPath string) *Loader {
	return &Loader{
		cgroupPath: cgroupPath,
	}
}

// CgroupPath returns the configured cgroup path.
func (l *Loader) CgroupPath() string {
	return l.cgroupPath
}

// OriginalDst represents the original destination before redirection.
type OriginalDst struct {
	IP4    uint32
	Port   uint16
	Family uint8
	_      uint8 // padding
}
