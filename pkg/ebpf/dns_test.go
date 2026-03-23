//go:build linux

package ebpf

import (
	"net"
	"testing"
	"unsafe"

	ciliumebpf "github.com/cilium/ebpf"
)

// createTrackedTgidsMap creates a BPF LRU hash map matching the tracked_tgids spec.
func createTrackedTgidsMap(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type:       ciliumebpf.LRUHash,
		KeySize:    4, // __u32 tgid
		ValueSize:  1, // __u8
		MaxEntries: 1024,
	})
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// createDNSIPMap creates a BPF LRU hash map matching the dns_ip_map spec.
func createDNSIPMap(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type:       ciliumebpf.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(dnsIPKey{})),
		ValueSize:  uint32(unsafe.Sizeof(dnsIPVal{})),
		MaxEntries: 4096,
	})
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// createConnIPMap creates a BPF LRU hash map matching the conn_ip_map spec.
func createConnIPMap(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type:       ciliumebpf.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(connIPKey{})),
		ValueSize:  16, // __u8 ip[16]
		MaxEntries: 4096,
	})
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// createDNSConfigMap creates a BPF array map matching the dns_config spec.
func createDNSConfigMap(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type:       ciliumebpf.Array,
		KeySize:    4,  // __u32 index
		ValueSize:  16, // __u8 ip[16]
		MaxEntries: 4,
	})
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// ---- Struct size assertions ----

func TestDNSStructSizes(t *testing.T) {
	if got, want := unsafe.Sizeof(dnsIPKey{}), uintptr(24); got != want {
		t.Errorf("dnsIPKey size = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(dnsIPVal{}), uintptr(48); got != want {
		t.Errorf("dnsIPVal size = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(connIPKey{}), uintptr(8); got != want {
		t.Errorf("connIPKey size = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(sslFdKey{}), uintptr(16); got != want {
		t.Errorf("sslFdKey size = %d, want %d", got, want)
	}
}

// ---- tracked_tgids map tests ----

func TestTrackedTGIDs_AddRemove(t *testing.T) {
	m := createTrackedTgidsMap(t)

	tgid := uint32(1234)
	val := uint8(1)

	if err := m.Put(tgid, val); err != nil {
		t.Fatalf("Put tgid: %v", err)
	}

	var got uint8
	if err := m.Lookup(tgid, &got); err != nil {
		t.Fatalf("Lookup tgid: %v", err)
	}
	if got != 1 {
		t.Errorf("expected value=1, got %d", got)
	}

	if err := m.Delete(tgid); err != nil {
		t.Fatalf("Delete tgid: %v", err)
	}

	if err := m.Lookup(tgid, &got); err == nil {
		t.Error("expected lookup to fail after delete")
	}
}

// ---- dns_ip_map tests ----

func TestDNSIPMap_IPv4MappedKey(t *testing.T) {
	m := createDNSIPMap(t)

	// Store an IPv4-mapped IPv6 address for tgid=42
	var key dnsIPKey
	key.Tgid = 42
	ip := net.ParseIP("54.187.230.1").To16()
	copy(key.IP[:], ip)

	hostname := "api.stripe.com"
	var val dnsIPVal
	copy(val.Hostname[:], hostname)
	val.HostLen = uint32(len(hostname))
	val.TTLSec = 60

	if err := m.Put(key, val); err != nil {
		t.Fatalf("Put dns_ip_map: %v", err)
	}

	var got dnsIPVal
	if err := m.Lookup(key, &got); err != nil {
		t.Fatalf("Lookup dns_ip_map: %v", err)
	}

	if got.HostLen != uint32(len(hostname)) {
		t.Errorf("HostLen = %d, want %d", got.HostLen, len(hostname))
	}
	if string(got.Hostname[:got.HostLen]) != hostname {
		t.Errorf("Hostname = %q, want %q", string(got.Hostname[:got.HostLen]), hostname)
	}
}

func TestDNSIPMap_IPv6Key(t *testing.T) {
	m := createDNSIPMap(t)

	var key dnsIPKey
	key.Tgid = 99
	ip := net.ParseIP("2606:4700::6810:84e5").To16()
	copy(key.IP[:], ip)

	var val dnsIPVal
	copy(val.Hostname[:], "cloudflare.com")
	val.HostLen = 14

	if err := m.Put(key, val); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var got dnsIPVal
	if err := m.Lookup(key, &got); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.HostLen != 14 {
		t.Errorf("HostLen = %d, want 14", got.HostLen)
	}
}

func TestDNSIPMap_TGIDIsolation(t *testing.T) {
	m := createDNSIPMap(t)

	ip := net.ParseIP("1.2.3.4").To16()

	// Same IP, two different TGIDs
	var keyA, keyB dnsIPKey
	keyA.Tgid = 100
	copy(keyA.IP[:], ip)
	keyB.Tgid = 200
	copy(keyB.IP[:], ip)

	var valA, valB dnsIPVal
	copy(valA.Hostname[:], "alpha.example.com")
	valA.HostLen = 17
	copy(valB.Hostname[:], "beta.example.com")
	valB.HostLen = 16

	if err := m.Put(keyA, valA); err != nil {
		t.Fatalf("Put A: %v", err)
	}
	if err := m.Put(keyB, valB); err != nil {
		t.Fatalf("Put B: %v", err)
	}

	var gotA, gotB dnsIPVal
	if err := m.Lookup(keyA, &gotA); err != nil {
		t.Fatalf("Lookup A: %v", err)
	}
	if err := m.Lookup(keyB, &gotB); err != nil {
		t.Fatalf("Lookup B: %v", err)
	}

	if string(gotA.Hostname[:gotA.HostLen]) != "alpha.example.com" {
		t.Errorf("got A hostname %q, want alpha.example.com", string(gotA.Hostname[:gotA.HostLen]))
	}
	if string(gotB.Hostname[:gotB.HostLen]) != "beta.example.com" {
		t.Errorf("got B hostname %q, want beta.example.com", string(gotB.Hostname[:gotB.HostLen]))
	}
}

// ---- conn_ip_map tests ----

func TestConnIPMap_BasicStore(t *testing.T) {
	m := createConnIPMap(t)

	key := connIPKey{Tgid: 55, Fd: 7}
	ip := net.ParseIP("10.96.0.10").To16() // ClusterIP
	var val [16]byte
	copy(val[:], ip)

	if err := m.Put(key, val); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var got [16]byte
	if err := m.Lookup(key, &got); err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if got != val {
		t.Errorf("IP mismatch: got %v, want %v", got, val)
	}
}

// ---- dns_config map tests ----

func TestDNSConfigMap_SetDNSServer(t *testing.T) {
	m := createDNSConfigMap(t)

	ip := net.ParseIP("10.96.0.10").To16()
	var val [16]byte
	copy(val[:], ip)

	idx := uint32(0)
	if err := m.Put(idx, val); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var got [16]byte
	if err := m.Lookup(idx, &got); err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if got != val {
		t.Errorf("DNS IP mismatch: got %v, want %v", got, val)
	}
}

func TestDNSConfigMap_MultipleServers(t *testing.T) {
	m := createDNSConfigMap(t)

	servers := []string{"10.96.0.10", "10.96.0.11", "10.96.0.12", "10.96.0.13"}
	for i, s := range servers {
		ip := net.ParseIP(s).To16()
		var val [16]byte
		copy(val[:], ip)
		if err := m.Put(uint32(i), val); err != nil {
			t.Fatalf("Put[%d]: %v", i, err)
		}
	}

	// Verify all 4 entries
	for i, s := range servers {
		var got [16]byte
		if err := m.Lookup(uint32(i), &got); err != nil {
			t.Fatalf("Lookup[%d]: %v", i, err)
		}
		want := net.ParseIP(s).To16()
		for j := range want {
			if got[j] != want[j] {
				t.Errorf("server[%d] IP byte %d = %d, want %d", i, j, got[j], want[j])
			}
		}
	}
}
