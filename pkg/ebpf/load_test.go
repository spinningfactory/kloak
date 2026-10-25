//go:build linux

package ebpf

import (
	"errors"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
)

// verifierBudget is how many instructions the verifier may walk for one
// program: half the kernel's limit (BPF_COMPLEXITY_LIMIT_INSNS, 1M). The
// count changes a lot between kernels for the same program (the SNI kprobe
// took 160K on 6.8 and 859K on 7.2), so a program close to the limit on one
// kernel is one verifier change away from being rejected on the next.
const verifierBudget = 500_000

func loadTestObjects(t *testing.T) *tlsuprobeObjects {
	t.Helper()
	objs := &tlsuprobeObjects{}
	if err := loadTlsuprobeObjects(objs, nil); err != nil {
		skipUnlessRejected(t, err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return objs
}

// skipUnlessRejected skips the test when the objects can't be loaded here (no
// root, no BPF), but fails it when the verifier rejected a program: that is a
// kloak bug on this kernel, and a kernel matrix must not pass by skipping.
// KLOAK_REQUIRE_BPF=1 (CI's kernel matrix) makes every load failure fatal.
func skipUnlessRejected(t *testing.T, err error) {
	t.Helper()
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		t.Fatalf("the verifier rejected a program: %-20v", ve)
	}
	if os.Getenv("KLOAK_REQUIRE_BPF") == "1" {
		t.Fatalf("eBPF objects did not load: %v", err)
	}
	t.Skipf("eBPF objects not available (need Linux kernel 5.17+): %v", err)
}

// TestVerifierBudget loads every program on its own, so that one rejection
// doesn't hide the others, and checks its verifier cost against
// verifierBudget.
func TestVerifierBudget(t *testing.T) {
	spec, err := loadTlsuprobe()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range slices.Sorted(maps.Keys(spec.Programs)) {
		t.Run(name, func(t *testing.T) {
			one := spec.Copy()
			one.Programs = map[string]*ebpf.ProgramSpec{name: one.Programs[name]}
			coll, err := ebpf.NewCollection(one)
			if err != nil {
				skipUnlessRejected(t, err)
			}
			defer coll.Close()

			info, err := coll.Programs[name].Info()
			if err != nil {
				t.Fatal(err)
			}
			n, ok := info.VerifiedInstructions()
			if !ok {
				t.Skip("this kernel doesn't report the verifier's cost (5.16+)")
			}
			t.Logf("verified %d instructions (budget %d)", n, verifierBudget)
			if n > verifierBudget {
				t.Errorf("%d verified instructions is over the budget of %d", n, verifierBudget)
			}
		})
	}
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
