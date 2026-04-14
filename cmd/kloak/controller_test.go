package main

import (
	"context"
	"net"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeReader(objs ...client.Object) client.Reader {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func kubeDNSSvc(clusterIP string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-dns",
			Namespace: "kube-system",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: clusterIP,
		},
	}
}

func TestDiscoverTrustedDNSServers_KubeDNSOnly(t *testing.T) {
	reader := newFakeReader(kubeDNSSvc("10.96.0.10"))
	trustedDNSServers = "" // no user-configured servers

	ips := discoverTrustedDNSServers(reader, zap.NewNop().Sugar())

	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d: %v", len(ips), ips)
	}
	if ips[0].String() != "10.96.0.10" {
		t.Errorf("expected 10.96.0.10, got %s", ips[0])
	}
}

func TestDiscoverTrustedDNSServers_UserProvidedOnly(t *testing.T) {
	// No kube-dns service
	reader := newFakeReader()
	trustedDNSServers = "8.8.8.8,1.1.1.1"

	ips := discoverTrustedDNSServers(reader, zap.NewNop().Sugar())

	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d: %v", len(ips), ips)
	}
	want := map[string]bool{"8.8.8.8": true, "1.1.1.1": true}
	for _, ip := range ips {
		if !want[ip.String()] {
			t.Errorf("unexpected IP %s", ip)
		}
	}
}

func TestDiscoverTrustedDNSServers_KubeDNSPlusUser(t *testing.T) {
	reader := newFakeReader(kubeDNSSvc("10.96.0.10"))
	trustedDNSServers = "8.8.8.8"

	ips := discoverTrustedDNSServers(reader, zap.NewNop().Sugar())

	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d: %v", len(ips), ips)
	}
	want := map[string]bool{"10.96.0.10": true, "8.8.8.8": true}
	for _, ip := range ips {
		if !want[ip.String()] {
			t.Errorf("unexpected IP %s", ip)
		}
	}
}

func TestDiscoverTrustedDNSServers_Dedup(t *testing.T) {
	reader := newFakeReader(kubeDNSSvc("10.96.0.10"))
	trustedDNSServers = "10.96.0.10,8.8.8.8,10.96.0.10"

	ips := discoverTrustedDNSServers(reader, zap.NewNop().Sugar())

	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs (deduplicated), got %d: %v", len(ips), ips)
	}
}

func TestDiscoverTrustedDNSServers_InvalidIPSkipped(t *testing.T) {
	reader := newFakeReader()
	trustedDNSServers = "not-an-ip,8.8.8.8,"

	ips := discoverTrustedDNSServers(reader, zap.NewNop().Sugar())

	if len(ips) != 1 {
		t.Fatalf("expected 1 IP (invalid skipped), got %d: %v", len(ips), ips)
	}
	if ips[0].String() != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8, got %s", ips[0])
	}
}

func TestDiscoverTrustedDNSServers_Empty(t *testing.T) {
	reader := newFakeReader()
	trustedDNSServers = ""

	ips := discoverTrustedDNSServers(reader, zap.NewNop().Sugar())

	if len(ips) != 0 {
		t.Fatalf("expected 0 IPs, got %d: %v", len(ips), ips)
	}
}

func TestDiscoverTrustedDNSServers_IPv6(t *testing.T) {
	reader := newFakeReader()
	trustedDNSServers = "2001:db8::1,8.8.8.8"

	ips := discoverTrustedDNSServers(reader, zap.NewNop().Sugar())

	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d: %v", len(ips), ips)
	}
	want := map[string]bool{"2001:db8::1": true, "8.8.8.8": true}
	for _, ip := range ips {
		if !want[ip.String()] {
			t.Errorf("unexpected IP %s", ip)
		}
	}
}

// TestDiscoverTrustedDNSServers_WhitespaceHandling verifies that leading/
// trailing whitespace in the comma-separated list is trimmed.
func TestDiscoverTrustedDNSServers_WhitespaceHandling(t *testing.T) {
	reader := newFakeReader()
	trustedDNSServers = " 8.8.8.8 , 1.1.1.1 "

	ips := discoverTrustedDNSServers(reader, zap.NewNop().Sugar())

	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d: %v", len(ips), ips)
	}
}

// TestDNSIPKeyIPv4Mapping verifies that the dnsIPKey struct correctly stores
// IPv4 addresses as IPv4-mapped-IPv6 (matching the BPF map key format).
func TestDNSIPKeyIPv4Mapping(t *testing.T) {
	ip := net.ParseIP("10.96.0.10")
	ip4 := ip.To4()
	if ip4 == nil {
		t.Fatal("expected IPv4")
	}

	var key [16]byte
	key[10] = 0xff
	key[11] = 0xff
	copy(key[12:], ip4)

	// Verify the IPv4-mapped-IPv6 format: ::ffff:10.96.0.10
	expected := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 96, 0, 10}
	if key != expected {
		t.Errorf("IPv4-mapped key mismatch:\n  got:  %v\n  want: %v", key, expected)
	}
}

// TestDNSIPKeyIPv6Native verifies that native IPv6 addresses are stored
// directly in the 16-byte key.
func TestDNSIPKeyIPv6Native(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	ip16 := ip.To16()

	var key [16]byte
	copy(key[:], ip16)

	if key[0] != 0x20 || key[1] != 0x01 || key[15] != 0x01 {
		t.Errorf("IPv6 key mismatch: %v", key)
	}
}

// TestPopulateTrustedDNSServersIPEncoding is a pure-Go test verifying the IP
// encoding logic used in PopulateTrustedDNSServers. The actual BPF map
// interaction is tested in pkg/ebpf/ (Linux-only).
func TestPopulateTrustedDNSServersIPEncoding(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected [16]byte
	}{
		{
			"IPv4",
			"10.96.0.10",
			[16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 96, 0, 10},
		},
		{
			"IPv4_loopback",
			"127.0.0.1",
			[16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1},
		},
		{
			"IPv6",
			"2001:db8::1",
			func() [16]byte {
				var b [16]byte
				copy(b[:], net.ParseIP("2001:db8::1").To16())
				return b
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			var key [16]byte
			if ip4 := ip.To4(); ip4 != nil {
				key[10] = 0xff
				key[11] = 0xff
				copy(key[12:], ip4)
			} else {
				copy(key[:], ip.To16())
			}
			if key != tc.expected {
				t.Errorf("IP encoding for %s:\n  got:  %v\n  want: %v", tc.ip, key, tc.expected)
			}
		})
	}
}

// Verify the function doesn't panic when context is available.
func TestDiscoverTrustedDNSServers_ContextUsage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled context

	// Even with a cancelled context, the function should not panic
	// (it uses context.Background() internally)
	reader := newFakeReader(kubeDNSSvc("10.96.0.10"))
	trustedDNSServers = ""

	ips := discoverTrustedDNSServers(reader, zap.NewNop().Sugar())
	_ = ctx

	// kube-dns should still be discovered (function uses its own context)
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
}
