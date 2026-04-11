//go:build linux

package ebpf

import (
	"net"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
)

// createTestTrustedDNSMap creates a BPF hash map matching the trusted_dns_servers spec.
func createTestTrustedDNSMap(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type:       ciliumebpf.Hash,
		KeySize:    16, // dns_ip_key: __u8 ip[16]
		ValueSize:  1,  // __u8
		MaxEntries: 32,
	})
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// createTestDNSWhitelistFlag creates a BPF array map matching dns_whitelist_enabled spec.
func createTestDNSWhitelistFlag(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type:       ciliumebpf.Array,
		KeySize:    4, // __u32
		ValueSize:  1, // __u8
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// populateTrustedDNSServers is a test-friendly version of the PopulateTrustedDNSServers
// logic that operates directly on BPF maps, avoiding the dependency on the
// generated tlsuprobeObjects struct.
func populateTrustedDNSServers(t *testing.T, flagMap, dnsMap *ciliumebpf.Map, ips []net.IP) {
	t.Helper()

	// Enable the whitelist flag.
	flagKey := uint32(0)
	val := uint8(1)
	if err := flagMap.Update(flagKey, val, 0); err != nil {
		t.Fatalf("enabling DNS whitelist: %v", err)
	}

	for _, ip := range ips {
		var key dnsIPKey
		ip4 := ip.To4()
		if ip4 != nil {
			key.IP[10] = 0xff
			key.IP[11] = 0xff
			copy(key.IP[12:], ip4)
		} else {
			copy(key.IP[:], ip.To16())
		}
		if err := dnsMap.Update(&key, &val, 0); err != nil {
			t.Fatalf("adding trusted DNS server %s: %v", ip, err)
		}
	}
}

func TestPopulateTrustedDNS_IPv4(t *testing.T) {
	dnsMap := createTestTrustedDNSMap(t)
	flagMap := createTestDNSWhitelistFlag(t)

	populateTrustedDNSServers(t, flagMap, dnsMap, []net.IP{net.ParseIP("10.96.0.10")})

	// Verify whitelist flag is enabled.
	var flagVal uint8
	if err := flagMap.Lookup(uint32(0), &flagVal); err != nil {
		t.Fatalf("whitelist flag lookup failed: %v", err)
	}
	if flagVal != 1 {
		t.Errorf("expected whitelist enabled (1), got %d", flagVal)
	}

	// Verify the IPv4 address is stored as IPv4-mapped-IPv6.
	var key dnsIPKey
	key.IP[10] = 0xff
	key.IP[11] = 0xff
	copy(key.IP[12:], net.ParseIP("10.96.0.10").To4())

	var val uint8
	if err := dnsMap.Lookup(&key, &val); err != nil {
		t.Fatalf("trusted DNS entry not found: %v", err)
	}
	if val != 1 {
		t.Errorf("expected value 1, got %d", val)
	}
}

func TestPopulateTrustedDNS_IPv6(t *testing.T) {
	dnsMap := createTestTrustedDNSMap(t)
	flagMap := createTestDNSWhitelistFlag(t)

	populateTrustedDNSServers(t, flagMap, dnsMap, []net.IP{net.ParseIP("2001:db8::1")})

	var key dnsIPKey
	copy(key.IP[:], net.ParseIP("2001:db8::1").To16())

	var val uint8
	if err := dnsMap.Lookup(&key, &val); err != nil {
		t.Fatalf("IPv6 DNS entry not found: %v", err)
	}
}

func TestPopulateTrustedDNS_Multiple(t *testing.T) {
	dnsMap := createTestTrustedDNSMap(t)
	flagMap := createTestDNSWhitelistFlag(t)

	ips := []net.IP{
		net.ParseIP("10.96.0.10"),
		net.ParseIP("8.8.8.8"),
		net.ParseIP("2001:db8::1"),
	}
	populateTrustedDNSServers(t, flagMap, dnsMap, ips)

	for _, ip := range ips {
		var key dnsIPKey
		if ip4 := ip.To4(); ip4 != nil {
			key.IP[10] = 0xff
			key.IP[11] = 0xff
			copy(key.IP[12:], ip4)
		} else {
			copy(key.IP[:], ip.To16())
		}
		var val uint8
		if err := dnsMap.Lookup(&key, &val); err != nil {
			t.Errorf("DNS entry for %s not found: %v", ip, err)
		}
	}
}

func TestPopulateTrustedDNS_Empty(t *testing.T) {
	dnsMap := createTestTrustedDNSMap(t)
	flagMap := createTestDNSWhitelistFlag(t)

	// Empty list should still enable the whitelist (fail-closed).
	populateTrustedDNSServers(t, flagMap, dnsMap, nil)

	var flagVal uint8
	if err := flagMap.Lookup(uint32(0), &flagVal); err != nil {
		t.Fatalf("whitelist flag lookup failed: %v", err)
	}
	if flagVal != 1 {
		t.Errorf("expected whitelist enabled even with empty list (fail-closed), got %d", flagVal)
	}
}

func TestPopulateTrustedDNS_IPv4NotFoundAsRawIPv4(t *testing.T) {
	dnsMap := createTestTrustedDNSMap(t)
	flagMap := createTestDNSWhitelistFlag(t)

	populateTrustedDNSServers(t, flagMap, dnsMap, []net.IP{net.ParseIP("10.96.0.10")})

	// Looking up the raw 4-byte IPv4 (NOT mapped) should fail.
	// This ensures the BPF map uses the IPv4-mapped-IPv6 format consistently.
	var rawKey dnsIPKey
	copy(rawKey.IP[:4], net.ParseIP("10.96.0.10").To4())
	var val uint8
	if err := dnsMap.Lookup(&rawKey, &val); err == nil {
		t.Error("raw IPv4 key should NOT match; only IPv4-mapped-IPv6 should be stored")
	}
}

func TestPopulateTrustedDNS_LookupMiss(t *testing.T) {
	dnsMap := createTestTrustedDNSMap(t)
	flagMap := createTestDNSWhitelistFlag(t)

	populateTrustedDNSServers(t, flagMap, dnsMap, []net.IP{net.ParseIP("10.96.0.10")})

	// An IP that was NOT added should not be found.
	var key dnsIPKey
	key.IP[10] = 0xff
	key.IP[11] = 0xff
	copy(key.IP[12:], net.ParseIP("8.8.8.8").To4())

	var val uint8
	if err := dnsMap.Lookup(&key, &val); err == nil {
		t.Error("untrusted IP should not be in the map")
	}
}
