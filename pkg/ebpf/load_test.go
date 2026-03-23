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
	if objs.BpfPhase2Rewrite == nil {
		t.Error("BpfPhase2Rewrite program not loaded")
	}
	if objs.BpfUprobeGoTlsWrite == nil {
		t.Error("BpfUprobeGoTlsWrite program not loaded")
	}
	if objs.BpfUprobeSslWrite == nil {
		t.Error("BpfUprobeSslWrite program not loaded")
	}
}

func TestTailCallWiring(t *testing.T) {
	objs := loadTestObjects(t)

	// Wire the tail call like NewTLSUprobeManager does
	phase2FD := uint32(objs.BpfPhase2Rewrite.FD())
	if err := objs.ProgArray.Update(uint32(0), &phase2FD, 0); err != nil {
		t.Fatalf("failed to wire tail call: %v", err)
	}

	// Verify the entry exists (prog_array remaps FDs internally,
	// so we just check lookup succeeds, not the exact value)
	var fd uint32
	if err := objs.ProgArray.Lookup(uint32(0), &fd); err != nil {
		t.Fatalf("failed to read tail call entry: %v", err)
	}
}

func TestSecretMapOperations(t *testing.T) {
	objs := loadTestObjects(t)

	// Put
	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
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

func TestConnHostsMapOperations(t *testing.T) {
	objs := loadTestObjects(t)

	type connKey struct {
		SslPtr uint64
		Tgid   uint32
		Pad    uint32
	}
	type connHost struct {
		HostLen  uint32
		Hostname [32]byte
	}

	key := connKey{SslPtr: 0xdeadbeef, Tgid: 1234}
	val := connHost{HostLen: 11}
	copy(val.Hostname[:], "httpbin.org")

	if err := objs.ConnHosts.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Fatalf("failed to update conn_hosts: %v", err)
	}

	var got connHost
	if err := objs.ConnHosts.Lookup(&key, &got); err != nil {
		t.Fatalf("failed to lookup conn_hosts: %v", err)
	}
	if got.HostLen != 11 {
		t.Errorf("expected hostLen=11, got %d", got.HostLen)
	}
	if string(got.Hostname[:got.HostLen]) != "httpbin.org" {
		t.Errorf("expected 'httpbin.org', got %q", string(got.Hostname[:got.HostLen]))
	}
}
