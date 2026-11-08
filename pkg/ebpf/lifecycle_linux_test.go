//go:build linux

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

func dirIno(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// TestGCCgroupMaps checks that the sweep deletes the entries of the
// cgroup-keyed maps for cgroups that no longer exist, and keeps those of
// cgroups under kubepods and of cgroups kloak tracks.
func TestGCCgroupMaps(t *testing.T) {
	objs := loadTestObjects(t)
	// A directory tree stands in for the kubepods cgroup: cgroup IDs are
	// directory inodes.
	root := t.TempDir()
	pod := filepath.Join(root, "kubepods-besteffort-pod1.slice")
	ctr := filepath.Join(pod, "cri-containerd-abc.scope")
	if err := os.MkdirAll(ctr, 0o755); err != nil {
		t.Fatal(err)
	}
	live, gone, trackedOnly := dirIno(t, ctr), uint64(1<<40+1), uint64(1<<40+2)

	m := &TLSUprobeManager{objs: objs, log: zap.NewNop().Sugar(), kubepods: root}
	m.cgroupPaths.Store(trackedOnly, "/elsewhere")
	one := uint8(1)
	for _, id := range []uint64{live, gone, trackedOnly} {
		if err := objs.TrackedCgroups.Update(id, &one, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		key := tlsuprobeTlsBinaryKey{CgroupId: id, ExeInode: 77}
		if err := objs.TlsStrategy.Update(&key, &one, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		var off bpfTLSOffsets
		if err := objs.TlsOffsetConfig.Update(&key, &off, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}

	n, err := m.gcCgroupMaps()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("deleted %d entries, want the gone cgroup's 3", n)
	}
	var v uint8
	for _, id := range []uint64{live, trackedOnly} {
		if err := objs.TrackedCgroups.Lookup(id, &v); err != nil {
			t.Errorf("cgroup %d: %v", id, err)
		}
		key := tlsuprobeTlsBinaryKey{CgroupId: id, ExeInode: 77}
		if err := objs.TlsStrategy.Lookup(&key, &v); err != nil {
			t.Errorf("tls_strategy of cgroup %d: %v", id, err)
		}
	}
	if err := objs.TrackedCgroups.Lookup(gone, &v); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("gone cgroup still tracked: %v", err)
	}
	key := tlsuprobeTlsBinaryKey{CgroupId: gone, ExeInode: 77}
	var off bpfTLSOffsets
	if err := objs.TlsOffsetConfig.Lookup(&key, &off); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("gone cgroup's offsets kept: %v", err)
	}

	// Untracking a container deletes its per-binary entries at once.
	if err := m.UntrackExitedCgroup(live); err != nil {
		t.Fatal(err)
	}
	key = tlsuprobeTlsBinaryKey{CgroupId: live, ExeInode: 77}
	if err := objs.TlsStrategy.Lookup(&key, &v); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("untracked cgroup's tls_strategy kept: %v", err)
	}
}

// TestTCLinkLive checks the kernel check of a tc attachment: live while its
// interface is there, gone with it, for TCX and for cls_bpf.
func TestTCLinkLive(t *testing.T) {
	for _, mode := range []TCAttachMode{TCAttachTCX, TCAttachClsact} {
		t.Run(string(mode), func(t *testing.T) {
			e := newTCTestEnv(t)
			e.inTestNS(t)
			veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "kl-test0"}, PeerName: "kl-peer0"}
			if err := netlink.LinkAdd(veth); err != nil {
				t.Skipf("creating a veth pair: %v", err)
			}
			l, err := netlink.LinkByName(veth.Name)
			if err != nil {
				t.Fatal(err)
			}
			c, err := testManager(mode).attachTCProgram(e.prog, l.Attrs().Index, true, e.nsFile)
			if errors.Is(err, ebpf.ErrNotSupported) {
				t.Skip("kernel has no TCX")
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == TCAttachTCX {
				if _, ok := c.(link.Link); !ok {
					t.Fatalf("got %T, want a TCX link", c)
				}
			}
			if !tcLinkLive(c) {
				t.Error("attachment not live on its interface")
			}
			if err := netlink.LinkDel(l); err != nil {
				t.Fatal(err)
			}
			if tcLinkLive(c) {
				t.Error("attachment live after its interface was deleted")
			}
			if err := c.Close(); err != nil {
				t.Errorf("closing an attachment whose interface is gone: %v", err)
			}
		})
	}
}
