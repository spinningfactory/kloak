//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

func loadTestObjects(t *testing.T) *tlsuprobeObjects {
	t.Helper()
	objs := &tlsuprobeObjects{}
	if err := loadTlsuprobeObjects(objs, nil); err != nil {
		t.Skipf("eBPF objects not available (need Linux kernel 5.17+): %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return objs
}

func TestLoadObjects(t *testing.T) {
	objs := loadTestObjects(t)

	// Verify all expected programs were loaded
	if objs.BpfXorPath == nil {
		t.Error("BpfXorPath program not loaded")
	}
	if objs.BpfH_extract == nil {
		t.Error("BpfH_extract program not loaded")
	}
	if objs.BpfUprobeGoTlsWrite == nil {
		t.Error("BpfUprobeGoTlsWrite program not loaded")
	}
	if objs.BpfUprobeSslWrite == nil {
		t.Error("BpfUprobeSslWrite program not loaded")
	}
	if objs.KprobeUdpRecvmsg == nil {
		t.Error("KprobeUdpRecvmsg program not loaded")
	}
	if objs.KretprobeUdpRecvmsg == nil {
		t.Error("KretprobeUdpRecvmsg program not loaded")
	}
	if objs.TpEnterConnect == nil {
		t.Error("TpEnterConnect program not loaded")
	}
	if objs.TpExitConnect == nil {
		t.Error("TpExitConnect program not loaded")
	}
	if objs.TpEnterClose == nil {
		t.Error("TpEnterClose program not loaded")
	}
}

func TestTailCallWiring(t *testing.T) {
	objs := loadTestObjects(t)

	// Wire the tail call like NewTLSUprobeManager does
	xorFD := uint32(objs.BpfXorPath.FD())
	if err := objs.ProgArray.Update(uint32(1), &xorFD, 0); err != nil {
		t.Fatalf("failed to wire tail call: %v", err)
	}

	// Verify the entry exists (prog_array remaps FDs internally,
	// so we just check lookup succeeds, not the exact value)
	var fd uint32
	if err := objs.ProgArray.Lookup(uint32(1), &fd); err != nil {
		t.Fatalf("failed to read tail call entry: %v", err)
	}
}

func TestSecretMapOperations(t *testing.T) {
	objs := loadTestObjects(t)

	// Put
	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	val.Len = 10
	copy(val.RealSecret[:], []byte("my-secret!"))

	if err := objs.SecretMap.Update(&key, &val, 0); err != nil {
		t.Fatalf("failed to put: %v", err)
	}

	// Get
	var got secretValue
	if err := objs.SecretMap.Lookup(&key, &got); err != nil {
		t.Fatalf("failed to get: %v", err)
	}
	if got.Len != 10 {
		t.Errorf("expected len=10, got %d", got.Len)
	}
	if string(got.RealSecret[:10]) != "my-secret!" {
		t.Errorf("expected 'my-secret!', got %q", string(got.RealSecret[:10]))
	}

	// Delete
	if err := objs.SecretMap.Delete(&key); err != nil {
		t.Fatalf("failed to delete: %v", err)
	}

	// Verify deleted
	if err := objs.SecretMap.Lookup(&key, &got); err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestDnsIpMapOperations(t *testing.T) {
	objs := loadTestObjects(t)

	key := dnsIPKey{}
	// IPv4-mapped-IPv6 for 1.2.3.4
	key.IP[10] = 0xff
	key.IP[11] = 0xff
	key.IP[12] = 1
	key.IP[13] = 2
	key.IP[14] = 3
	key.IP[15] = 4

	val := tlsuprobeDnsIpVal{HostLen: 11, TtlSec: 300}
	for i, c := range []byte("example.com") {
		val.Hostname[i] = int8(c)
	}

	if err := objs.DnsIpMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to update dns_ip_map: %v", err)
	}

	var got tlsuprobeDnsIpVal
	if err := objs.DnsIpMap.Lookup(&key, &got); err != nil {
		t.Fatalf("failed to lookup dns_ip_map: %v", err)
	}
	if got.HostLen != 11 {
		t.Errorf("expected hostLen=11, got %d", got.HostLen)
	}
	host := make([]byte, got.HostLen)
	for i := range host {
		host[i] = byte(got.Hostname[i])
	}
	if string(host) != "example.com" {
		t.Errorf("expected 'example.com', got %q", host)
	}
}

func TestConnIpMapOperations(t *testing.T) {
	objs := loadTestObjects(t)

	key := tlsuprobeConnIpKey{Tgid: 1234, Fd: 5}
	val := tlsuprobeConnIpVal{Port: 443}
	// IPv4-mapped-IPv6 for 10.0.0.1
	val.Ip[10] = 0xff
	val.Ip[11] = 0xff
	val.Ip[12] = 10
	val.Ip[13] = 0
	val.Ip[14] = 0
	val.Ip[15] = 1

	if err := objs.ConnIpMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to update conn_ip_map: %v", err)
	}

	var got tlsuprobeConnIpVal
	if err := objs.ConnIpMap.Lookup(&key, &got); err != nil {
		t.Fatalf("failed to lookup conn_ip_map: %v", err)
	}
	if got.Ip[15] != 1 || got.Ip[12] != 10 || got.Port != 443 {
		t.Errorf("expected IP 10.0.0.1 mapped, got different IP")
	}
}

func TestTrackedTgidsMapOperations(t *testing.T) {
	objs := loadTestObjects(t)

	tgid := uint32(5678)
	val := uint8(1)
	if err := objs.TrackedTgids.Update(tgid, &val, 0); err != nil {
		t.Fatalf("failed to track tgid: %v", err)
	}

	var got uint8
	if err := objs.TrackedTgids.Lookup(tgid, &got); err != nil {
		t.Fatalf("failed to lookup tracked tgid: %v", err)
	}
	if got != 1 {
		t.Errorf("expected tracked=1, got %d", got)
	}

	if err := objs.TrackedTgids.Delete(tgid); err != nil {
		t.Fatalf("failed to untrack tgid: %v", err)
	}
}

func TestWatchedHostsMapOperations(t *testing.T) {
	objs := loadTestObjects(t)

	var key watchedHostKey
	copy(key.Host[:], "api.stripe.com")
	val := uint8(1)

	if err := objs.WatchedHosts.Update(&key, &val, 0); err != nil {
		t.Fatalf("failed to update watched_hosts: %v", err)
	}

	var got uint8
	if err := objs.WatchedHosts.Lookup(&key, &got); err != nil {
		t.Fatalf("failed to lookup watched_hosts: %v", err)
	}
	if got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
}
