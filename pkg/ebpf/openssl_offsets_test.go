package ebpf

import (
	"testing"
)

func TestExtractMajorMinor(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"3.2.1", "3.2"},
		{"3.0.13", "3.0"},
		{"1.1.1w", "1.1"},
		{"3", "3"},
		{"3.4", "3.4"},
	}
	for _, tt := range tests {
		got := extractMajorMinor(tt.input)
		if got != tt.want {
			t.Errorf("extractMajorMinor(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFindVersionInData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "standard format",
			data: []byte("some data\x00OpenSSL 3.2.1 14 Jan 2025\x00more"),
			want: "3.2.1",
		},
		{
			name: "null terminated",
			data: []byte("OpenSSL 3.0.13\x00"),
			want: "3.0.13",
		},
		{
			name: "not present",
			data: []byte("BoringSSL something"),
			want: "",
		},
		{
			name: "partial match",
			data: []byte("OpenSSL "),
			want: "",
		},
		{
			name: "old format",
			data: []byte("OpenSSL 1.1.1w  11 Sep 2023\x00"),
			want: "1.1.1w",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findVersionInData(tt.data)
			if got != tt.want {
				t.Errorf("findVersionInData() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsLibSSL(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/usr/lib/libssl.so", true},
		{"/usr/lib/libssl.so.3", true},
		{"/proc/123/root/usr/lib/x86_64-linux-gnu/libssl.so.3", true},
		{"/usr/lib/libcrypto.so", false},
		{"/usr/lib/libboringssl.so", false},
		{"/app/demo-app", false},
	}
	for _, tt := range tests {
		if got := isLibSSL(tt.path); got != tt.want {
			t.Errorf("isLibSSL(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestContainsBytes(t *testing.T) {
	tests := []struct {
		data    []byte
		pattern []byte
		want    bool
	}{
		{[]byte("hello BoringSSL world"), []byte("BoringSSL"), true},
		{[]byte("hello OpenSSL world"), []byte("BoringSSL"), false},
		{[]byte("BoringSSL"), []byte("BoringSSL"), true},
		{[]byte("Boring"), []byte("BoringSSL"), false},
	}
	for _, tt := range tests {
		if got := containsBytes(tt.data, tt.pattern); got != tt.want {
			t.Errorf("containsBytes(%q, %q) = %v, want %v", tt.data, tt.pattern, got, tt.want)
		}
	}
}
