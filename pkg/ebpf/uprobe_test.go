//go:build linux

package ebpf

import "testing"

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
		// rustls-ffi
		{"librustls.so", true},
		{"librustls.so.0", true},
		{"librustls.so.0.14.0", true},
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
