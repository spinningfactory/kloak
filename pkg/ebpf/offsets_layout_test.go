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

// TestSecretACLKeyLayout pins secretACLKey to the generated struct
// secret_acl_key; a mismatch would make every lookup miss (fail closed for
// every pod).
func TestSecretACLKeyLayout(t *testing.T) {
	if got, want := binary.Size(secretACLKey{}), binary.Size(tlsuprobeSecretAclKey{}); got != want {
		t.Fatalf("secretACLKey is %d bytes, struct secret_acl_key is %d", got, want)
	}
}

// TestVirtualIPLayout pins the virtual IP map mirrors to the generated
// structs. These maps are pinned across restarts, so a change here is also a
// change to what a new controller finds in bpffs (prepareVirtualIPPins).
func TestVirtualIPLayout(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"vip_host_val", vipHostVal{}, tlsuprobeVipHostVal{}},
		{"vip_ip_val", vipIPVal{}, tlsuprobeVipIpVal{}},
		{"vip_config_val", vipConfigVal{}, tlsuprobeVipConfigVal{}},
		{"vip_upstream_val", vipUpstreamVal{}, tlsuprobeVipUpstreamVal{}},
		{"vip_pod_host_key", vipPodHostKey{}, tlsuprobeVipPodHostKey{}},
	} {
		if got, want := binary.Size(c.got), binary.Size(c.want); got != want {
			t.Errorf("%T is %d bytes, struct %s is %d", c.got, got, c.name, want)
		}
		if got, want := fieldNames(c.got), fieldNames(c.want); !slices.Equal(got, want) {
			t.Errorf("%T field order %v does not match struct %s %v", c.got, got, c.name, want)
		}
	}
}
