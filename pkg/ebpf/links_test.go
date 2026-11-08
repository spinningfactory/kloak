//go:build linux

package ebpf

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// countingLink is a link that counts how many times it was closed.
type countingLink struct {
	mu     *sync.Mutex
	closed *int
}

func (l countingLink) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	*l.closed++
	return nil
}

// fakeAttach returns an attach function making n links, and the number of
// times it ran.
func fakeAttach(n int) (func() ([]io.Closer, error), *int, *int) {
	var mu sync.Mutex
	attaches, closed := 0, 0
	return func() ([]io.Closer, error) {
		attaches++
		out := make([]io.Closer, n)
		for i := range out {
			out[i] = countingLink{&mu, &closed}
		}
		return out, nil
	}, &attaches, &closed
}

func closeAll(t *testing.T, links []io.Closer) {
	t.Helper()
	for _, l := range links {
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

var (
	libssl    = fileKey{ino: 803803, handle: "ovl:libssl"}
	libcrypto = fileKey{ino: 803802, handle: "ovl:libcrypto"}
	exeA      = fileKey{dev: 83, ino: 1001}
	exeB      = fileKey{dev: 83, ino: 1002}
)

// TestLinkRegistryDedup checks that a uprobe is attached once however many
// times the attach paths discover it (a container's processes, the exec
// events, NRI and the reconciler), and once per symbol and program.
func TestLinkRegistryDedup(t *testing.T) {
	var r linkRegistry
	attach, attaches, _ := fakeAttach(1)
	lib := uprobeLinkKey{file: libssl, symbol: "SSL_write", prog: progSSLWrite}
	for range 3 {
		if _, err := r.ensure(&lib, 1, attach); err != nil {
			t.Fatal(err)
		}
	}
	if *attaches != 1 {
		t.Fatalf("library probe attached %d times, want 1", *attaches)
	}
	for _, k := range []uprobeLinkKey{
		{file: libssl, symbol: "SSL_write_ex", prog: progSSLWrite},
		{file: libcrypto, symbol: "EVP_CipherInit_ex", prog: progEVPCipherInit},
		{pid: 7, start: 100, file: exeA, symbol: "SSL_write", prog: progSSLWrite},
		{pid: 7, start: 100, file: exeA, addr: 0x1234, prog: progSSLWrite},
	} {
		created, err := r.ensure(&k, 1, attach)
		if err != nil || !created {
			t.Fatalf("%+v: created=%v err=%v", k, created, err)
		}
	}
	if n, _ := r.counts(); n != 5 {
		t.Errorf("%d uprobes recorded, want 5", n)
	}

	// A failed attach is not recorded, so a later discovery attaches it.
	failed := uprobeLinkKey{file: libssl, symbol: "gnutls_record_send", prog: progSSLWrite}
	if _, err := r.ensure(&failed, 1, func() ([]io.Closer, error) { return nil, errors.New("no such symbol") }); err == nil {
		t.Fatal("attach error not returned")
	}
	if created, _ := r.ensure(&failed, 1, attach); !created {
		t.Fatal("failed attach was recorded")
	}
}

// TestLinkRegistrySharedImageLayer checks that containers of one image share
// the uprobes on its libraries, which fire for all of them: attached once,
// detached with the last container that needs them.
func TestLinkRegistrySharedImageLayer(t *testing.T) {
	var r linkRegistry
	attach, attaches, closed := fakeAttach(2) // EVP_CipherInit: entry + return
	evp := uprobeLinkKey{file: libcrypto, symbol: "EVP_CipherInit_ex", prog: progEVPCipherInit}
	for _, cg := range []uint64{1, 2, 3} {
		if _, err := r.ensure(&evp, cg, attach); err != nil {
			t.Fatal(err)
		}
	}
	if *attaches != 1 {
		t.Fatalf("shared library probe attached %d times, want 1", *attaches)
	}
	for _, cg := range []uint64{1, 3} {
		if links := r.releaseCgroup(cg); len(links) != 0 {
			t.Fatalf("releasing container %d detached %d links another container needs", cg, len(links))
		}
	}
	// Releasing a container twice, or one that needs nothing, is a no-op.
	if links := r.releaseCgroup(1); len(links) != 0 {
		t.Fatalf("releasing container 1 again detached %d links", len(links))
	}
	links := r.releaseCgroup(2)
	if len(links) != 2 {
		t.Fatalf("releasing the last container returned %d links, want 2", len(links))
	}
	closeAll(t, links)
	if *closed != 2 {
		t.Errorf("%d links closed, want 2", *closed)
	}
	if created, _ := r.ensure(&evp, 4, attach); !created {
		t.Error("probe still recorded after its last container was released")
	}
}

// TestLinkRegistryReleaseCgroupProcessScoped checks that untracking a
// container detaches its processes' own uprobes and keeps the others'.
func TestLinkRegistryReleaseCgroupProcessScoped(t *testing.T) {
	var r linkRegistry
	attach, _, _ := fakeAttach(1)
	mustEnsure(t, &r, uprobeLinkKey{pid: 7, start: 100, file: exeA, symbol: "crypto/tls.(*Conn).Write", prog: progGoTLSWrite}, 1, attach)
	mustEnsure(t, &r, uprobeLinkKey{pid: 8, start: 100, file: exeA, symbol: "crypto/tls.(*Conn).Write", prog: progGoTLSWrite}, 2, attach)
	if got := len(r.releaseCgroup(1)); got != 1 {
		t.Fatalf("releasing container 1 returned %d links, want 1", got)
	}
	if n, _ := r.counts(); n != 1 {
		t.Errorf("%d uprobes left, want container 2's", n)
	}
}

func mustEnsure(t *testing.T, r *linkRegistry, k uprobeLinkKey, cg uint64, attach func() ([]io.Closer, error)) {
	t.Helper()
	if _, err := r.ensure(&k, cg, attach); err != nil {
		t.Fatal(err)
	}
}

// TestLinkRegistryPIDReuse checks that the uprobes of a process are dropped
// when another process gets its PID, and those of an executable the process
// ran before an exec when it runs another, and nothing else.
func TestLinkRegistryPIDReuse(t *testing.T) {
	var r linkRegistry
	attach, _, _ := fakeAttach(1)
	old := uprobeLinkKey{pid: 7, start: 100, file: exeA, symbol: "SSL_write", prog: progSSLWrite}
	other := uprobeLinkKey{pid: 8, start: 100, file: exeA, symbol: "SSL_write", prog: progSSLWrite}
	lib := uprobeLinkKey{file: libssl, symbol: "SSL_write", prog: progSSLWrite}
	for _, k := range []uprobeLinkKey{old, other, lib} {
		mustEnsure(t, &r, k, 1, attach)
	}

	// The same process and executable: nothing goes.
	if got := r.retainProcess(7, 100, exeA); len(got) != 0 {
		t.Fatalf("retaining the running process dropped %d links", len(got))
	}
	// PID 7 is another process now (another start time).
	if got := r.retainProcess(7, 200, exeA); len(got) != 1 {
		t.Fatalf("PID reuse dropped %d links, want 1", len(got))
	}
	reused := uprobeLinkKey{pid: 7, start: 200, file: exeA, symbol: "SSL_write", prog: progSSLWrite}
	if created, _ := r.ensure(&reused, 1, attach); !created {
		t.Fatal("the new process with the PID found the old one's uprobe")
	}
	// It execs another binary.
	newExe := uprobeLinkKey{pid: 7, start: 200, file: exeB, symbol: "crypto/tls.(*Conn).Write", prog: progGoTLSWrite}
	mustEnsure(t, &r, newExe, 1, attach)
	if got := r.retainProcess(7, 200, exeB); len(got) != 1 {
		t.Fatalf("exec dropped %d links, want the old executable's 1", len(got))
	}
	if n, _ := r.counts(); n != 3 { // other, lib, newExe
		t.Errorf("%d uprobes left, want 3", n)
	}
}

// TestLinkRegistrySweepProcesses checks that the sweep drops the uprobes of
// processes that exited or exec'd, once per process, and keeps the
// libraries'.
func TestLinkRegistrySweepProcesses(t *testing.T) {
	var r linkRegistry
	attach, _, _ := fakeAttach(1)
	evpAttach, _, _ := fakeAttach(2)
	mustEnsure(t, &r, uprobeLinkKey{pid: 7, start: 100, file: exeA, symbol: "SSL_write", prog: progSSLWrite}, 1, attach)
	mustEnsure(t, &r, uprobeLinkKey{pid: 7, start: 100, file: exeA, symbol: "EVP_CipherInit_ex", prog: progEVPCipherInit}, 1, evpAttach)
	mustEnsure(t, &r, uprobeLinkKey{pid: 9, start: 100, file: exeA, symbol: "SSL_write", prog: progSSLWrite}, 1, attach)
	mustEnsure(t, &r, uprobeLinkKey{file: libssl, symbol: "SSL_write", prog: progSSLWrite}, 1, attach)

	asked := map[procExe]int{}
	got := r.sweepProcesses(func(p procExe) bool {
		asked[p]++
		return p.pid != 7
	})
	if len(got) != 3 { // pid 7's SSL_write and EVP pair
		t.Fatalf("sweep returned %d links, want 3", len(got))
	}
	for p, n := range asked {
		if n != 1 || p.pid == 0 {
			t.Errorf("asked about %+v %d times", p, n)
		}
	}
	if len(asked) != 2 {
		t.Errorf("asked about %d processes, want 2", len(asked))
	}
	if n, _ := r.counts(); n != 2 {
		t.Errorf("%d uprobes left, want 2", n)
	}
	if got := r.sweepProcesses(func(procExe) bool { return true }); got != nil {
		t.Errorf("a sweep with every process running returned %d links", len(got))
	}
}

func TestLinkRegistryDrain(t *testing.T) {
	var r linkRegistry
	attach, _, _ := fakeAttach(2)
	mustEnsure(t, &r, uprobeLinkKey{file: libcrypto, symbol: "EVP_CipherInit_ex", prog: progEVPCipherInit}, 1, attach)
	mustEnsure(t, &r, uprobeLinkKey{pid: 7, start: 1, file: exeA, symbol: "EVP_CipherInit_ex", prog: progEVPCipherInit}, 1, attach)
	if got := len(r.drain()); got != 4 {
		t.Fatalf("drain returned %d links, want 4", got)
	}
	if n, links := r.counts(); n != 0 || links != 0 {
		t.Errorf("after drain: %d uprobes, %d links", n, links)
	}
}

func TestParseProcStartTime(t *testing.T) {
	for _, c := range []struct {
		name string
		stat string
		want uint64
		err  bool
	}{
		{"plain", "4242 (python3) S 1 4242 4242 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 123456 1000 10 18446744073709551615", 123456, false},
		{"command with spaces and parens", "17 (a) b (c)) R 1 17 17 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 987 0 0", 987, false},
		{"truncated", "17 (sh) S 1 17", 0, true},
		{"no command", "garbage", 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseProcStartTime([]byte(c.stat))
			if (err != nil) != c.err || got != c.want {
				t.Errorf("got %d, %v; want %d, error %v", got, err, c.want, c.err)
			}
		})
	}
}

// TestProcessCurrent checks the liveness the sweep relies on against this
// process.
func TestProcessCurrent(t *testing.T) {
	pid := os.Getpid()
	start, err := procStartTime(pid)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := exeFileKey(pid)
	if err != nil {
		t.Fatal(err)
	}
	if !processCurrent(procExe{pid, start, exe}) {
		t.Error("this process is not current")
	}
	if processCurrent(procExe{pid, start + 1, exe}) {
		t.Error("another process with this PID is current")
	}
	if processCurrent(procExe{pid, start, fileKey{dev: exe.dev, ino: exe.ino + 1}}) {
		t.Error("this process is current with another executable")
	}
	if processCurrent(procExe{1 << 22, start, exe}) { // above the default pid_max
		t.Error("a missing process is current")
	}
}

// TestFileIdentity checks the identity of files outside an overlay: the
// file's (dev, ino), through links and symlinks.
func TestFileIdentity(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "libssl.so.3"), filepath.Join(dir, "libcrypto.so.3")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte(p), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(a, filepath.Join(dir, "hard")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libssl.so.3", filepath.Join(dir, "libssl.so")); err != nil {
		t.Fatal(err)
	}
	ka := mustIdentity(t, a)
	for _, p := range []string{filepath.Join(dir, "hard"), filepath.Join(dir, "libssl.so")} {
		if k := mustIdentity(t, p); k != ka {
			t.Errorf("%s: %+v, want %+v", p, k, ka)
		}
	}
	if kb := mustIdentity(t, b); kb == ka {
		t.Error("two files have one identity")
	}
	if _, err := fileIdentity(filepath.Join(dir, "missing")); err == nil {
		t.Error("no error for a missing file")
	}
}

func mustIdentity(t *testing.T, path string) fileKey {
	t.Helper()
	k, err := fileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestFileIdentityOverlaySharedLayer mounts two overlays over one lower
// directory, as two containers of one image are: a file of the layer has
// one identity in both, while stat gives each mount its own device. A file
// copied up into one container's upper directory is that container's own.
func TestFileIdentityOverlaySharedLayer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount overlayfs")
	}
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	if err := os.MkdirAll(filepath.Join(lower, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"libssl.so.3", "libcrypto.so.3"} {
		if err := os.WriteFile(filepath.Join(lower, "usr/lib", f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mount := func(name string) string {
		t.Helper()
		upper, work, merged := filepath.Join(dir, name, "upper"), filepath.Join(dir, name, "work"), filepath.Join(dir, name, "merged")
		for _, d := range []string{upper, work, merged} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
		if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
			t.Skipf("mounting overlayfs: %v", err)
		}
		t.Cleanup(func() { _ = unix.Unmount(merged, unix.MNT_DETACH) })
		return merged
	}
	a, b := mount("a"), mount("b")

	ka, kb := mustIdentity(t, filepath.Join(a, "usr/lib/libssl.so.3")), mustIdentity(t, filepath.Join(b, "usr/lib/libssl.so.3"))
	if ka.handle == "" {
		t.Skipf("no overlayfs file ID handle (needs Linux 6.6+): identity %+v", ka)
	}
	var sa, sb unix.Stat_t
	_ = unix.Stat(filepath.Join(a, "usr/lib/libssl.so.3"), &sa)
	_ = unix.Stat(filepath.Join(b, "usr/lib/libssl.so.3"), &sb)
	t.Logf("stat: dev %d and %d, ino %d and %d", sa.Dev, sb.Dev, sa.Ino, sb.Ino)
	if ka != kb {
		t.Errorf("one layer file has two identities: %+v and %+v", ka, kb)
	}
	if kc := mustIdentity(t, filepath.Join(a, "usr/lib/libcrypto.so.3")); kc == ka {
		t.Error("two layer files have one identity")
	}

	// Copy libssl up into a's upper directory, by writing to it, and
	// libcrypto into b's, by changing its mode only.
	c := mount("c")
	if err := os.WriteFile(filepath.Join(a, "usr/lib/libssl.so.3"), []byte("patched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(b, "usr/lib/libcrypto.so.3"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"usr/lib/libssl.so.3", "usr/lib/libcrypto.so.3"} {
		up := filepath.Join(a, f)
		if f == "usr/lib/libcrypto.so.3" {
			up = filepath.Join(b, f)
		}
		if mustIdentity(t, up) == mustIdentity(t, filepath.Join(c, f)) {
			t.Errorf("%s copied up into one container shares the layer file's identity", f)
		}
	}
}

// TestCheckPodTCReleasesOrphans checks that the sweep releases a pod netns
// entry no container is recorded in, and keeps one with a container that
// exited (its pod lives on).
func TestCheckPodTCReleasesOrphans(t *testing.T) {
	m := &TLSUprobeManager{log: zap.NewNop().Sugar()}
	var mu sync.Mutex
	closed := 0
	orphan := &podTC{attached: true, links: map[tcLinkKey]io.Closer{{netns: 1, ifindex: 5, ingress: true}: countingLink{&mu, &closed}}}
	kept := &podTC{attached: true, links: map[tcLinkKey]io.Closer{{netns: 1, ifindex: 6, ingress: true}: countingLink{&mu, &closed}}}
	m.podTC = map[uint64]*podTC{100: orphan, 200: kept}
	m.cgroupToNetns.Store(uint64(42), uint64(200)) // an exited container of the pod: no cgroupPaths entry

	repaired, released := m.checkPodTC()
	m.detachWG.Wait()
	if repaired != 0 || released != 1 {
		t.Fatalf("repaired %d, released %d; want 0 and 1", repaired, released)
	}
	if !orphan.released || len(orphan.links) != 0 {
		t.Error("the orphan entry is not released")
	}
	if closed != 1 {
		t.Errorf("%d links closed, want the orphan's 1", closed)
	}
	if _, ok := m.podTC[200]; !ok || kept.released {
		t.Error("the entry of a pod whose container exited was released")
	}
}

// TestReleaseCgroupNetns checks that a pod netns's tc program is detached
// with the last container recorded in it.
func TestReleaseCgroupNetns(t *testing.T) {
	m := &TLSUprobeManager{log: zap.NewNop().Sugar()}
	var mu sync.Mutex
	closed := 0
	e := &podTC{attached: true, links: map[tcLinkKey]io.Closer{
		{netns: 1, ifindex: 5, ingress: true}: countingLink{&mu, &closed},
		{netns: 7, ifindex: 2}:                countingLink{&mu, &closed},
	}}
	m.podTC = map[uint64]*podTC{300: e}
	m.cgroupToNetns.Store(uint64(1), uint64(300))
	m.cgroupToNetns.Store(uint64(2), uint64(300))

	m.ReleaseCgroupNetns(1)
	m.detachWG.Wait()
	if closed != 0 || e.released {
		t.Fatal("released while another container is recorded in the netns")
	}
	m.ReleaseCgroupNetns(2)
	m.detachWG.Wait()
	if closed != 2 || !e.released {
		t.Errorf("after the last container: %d links closed, released %v", closed, e.released)
	}
	if _, ok := m.podTC[300]; ok {
		t.Error("released entry still recorded")
	}
}
