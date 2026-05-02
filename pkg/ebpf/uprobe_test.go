//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestIsTLSLibrary(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// OpenSSL
		{"libssl.so", true},
		{"libssl.so.3", true},
		{"libssl.so.1.1", true},
		// BoringSSL
		{"libboringssl.so", true},
		{"libboringssl.so.1", true},
		// libcrypto
		{"libcrypto.so", true},
		{"libcrypto.so.3", true},
		// GnuTLS
		{"libgnutls.so", true},
		{"libgnutls.so.30", true},
		{"libgnutls.so.30.34.2", true},
		// Non-TLS libraries
		{"libc.so.6", false},
		{"libpthread.so.0", false},
		{"libssl-extra.so", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTLSLibrary(tt.name); got != tt.want {
				t.Errorf("isTLSLibrary(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestParseBPFLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  ebpf.LogLevel
	}{
		{"", 0},
		{"off", 0},
		{"OFF", 0},
		{"disabled", 0},
		{"none", 0},
		{"branch", ebpf.LogLevelBranch},
		{"BRANCH", ebpf.LogLevelBranch},
		{"  branch  ", ebpf.LogLevelBranch},
		{"instruction", ebpf.LogLevelInstruction},
		{"instructions", ebpf.LogLevelInstruction},
		{"stats", ebpf.LogLevelStats},
		{"branch,stats", ebpf.LogLevelBranch | ebpf.LogLevelStats},
		{"branch, stats", ebpf.LogLevelBranch | ebpf.LogLevelStats},
		{"unknown", 0},
		{"branch,unknown", ebpf.LogLevelBranch},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := parseBPFLogLevel(tt.input); got != tt.want {
				t.Errorf("parseBPFLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
