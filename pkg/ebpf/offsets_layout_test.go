//go:build linux

package ebpf

import (
	"encoding/binary"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestBPFTLSOffsetsLayout pins the hand-written bpfTLSOffsets mirror to the
// bpf2go-generated struct tls_offsets. A mismatch would otherwise only surface
// at runtime — as "Failed to push TLS offsets to BPF map" (size) or as the
// data plane silently reading the wrong offset (order) for every OpenSSL and
// BoringSSL process.
func TestBPFTLSOffsetsLayout(t *testing.T) {
	if got, want := binary.Size(bpfTLSOffsets{}), binary.Size(tlsuprobeTlsOffsets{}); got != want {
		t.Fatalf("bpfTLSOffsets is %d bytes, struct tls_offsets is %d — keep the mirror in uprobe.go in sync with tls_uprobe.c", got, want)
	}
	// Generated names are CamelCased from snake_case (ssl_to_wrl → SslToWrl);
	// compare case-insensitively so the mirror can keep Go initialisms.
	got, want := fieldNames(bpfTLSOffsets{}), fieldNames(tlsuprobeTlsOffsets{})
	if !slices.Equal(got, want) {
		t.Fatalf("bpfTLSOffsets field order %v does not match struct tls_offsets %v", got, want)
	}
}

func fieldNames(v any) []string {
	rt := reflect.TypeOf(v)
	names := make([]string, 0, rt.NumField())
	for i := range rt.NumField() {
		if name := rt.Field(i).Name; name != "_" {
			names = append(names, strings.ToLower(name))
		}
	}
	return names
}
