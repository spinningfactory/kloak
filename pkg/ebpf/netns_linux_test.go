//go:build linux

package ebpf

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// newNetns returns a handle to a new, empty network namespace (only a down
// lo), made on a thread that is retired afterwards.
func newNetns(t *testing.T) *os.File {
	t.Helper()
	ch := make(chan *os.File, 1)
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread is retired
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errCh <- err
			return
		}
		f, err := os.Open(threadNetnsPath)
		if err != nil {
			errCh <- err
			return
		}
		ch <- f
	}()
	select {
	case f := <-ch:
		t.Cleanup(func() { _ = f.Close() })
		return f
	case err := <-errCh:
		t.Skipf("cannot create a network namespace: %v", err)
		return nil
	}
}

// Keeps the main goroutine on the main thread (an init runs on it, before
// main), so that TestMain can run functions there for onMainThread.
func init() { runtime.LockOSThread() }

var mainThreadFuncs = make(chan func())

func TestMain(m *testing.M) {
	code := make(chan int)
	go func() { code <- m.Run() }()
	for {
		select {
		case f := <-mainThreadFuncs:
			f()
		case c := <-code:
			os.Exit(c)
		}
	}
}

// onMainThread runs f on the process's main thread.
func onMainThread(f func()) {
	done := make(chan struct{})
	mainThreadFuncs <- func() { f(); close(done) }
	<-done
}

// holdMainThread switches the main thread into ns until the test ends, as
// a worker setns'd into a pod's netns would.
func holdMainThread(t *testing.T, ns *os.File) {
	t.Helper()
	orig, err := os.Open(threadNetnsPath)
	if err != nil {
		t.Fatal(err)
	}
	onMainThread(func() { err = unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET) })
	if err != nil {
		_ = orig.Close()
		t.Fatalf("setns on the main thread: %v", err)
	}
	t.Cleanup(func() {
		onMainThread(func() { err = unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET) })
		_ = orig.Close()
		if err != nil {
			t.Fatalf("restoring the main thread's netns: %v", err)
		}
	})
}

// TestRunInNetnsRestoresWorkerThread checks that runInNetns returns its
// worker thread to the thread's own netns, not to the main thread's (which
// /proc/self/ns/net names), while another worker holds the main thread in a
// pod's netns.
func TestRunInNetnsRestoresWorkerThread(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (setns)")
	}
	want, err := netnsInode(threadNetnsPath)
	if err != nil {
		t.Fatal(err)
	}
	holdMainThread(t, newNetns(t))

	var tid int
	if _, err := runInNetns(newNetns(t), zap.NewNop().Sugar(), func() ([]io.Closer, error) {
		tid = unix.Gettid()
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := netnsInode(fmt.Sprintf("/proc/self/task/%d/ns/net", tid))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("worker thread %d left in netns %d, want %d", tid, got, want)
	}
}

// TestFindDefaultRouteInterfaceReadsThreadNetns checks that the default
// route is read in the calling thread's netns: an empty netns has none,
// whatever the main thread's netns has.
func TestFindDefaultRouteInterfaceReadsThreadNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (setns)")
	}
	if iface, err := findDefaultRouteInterface(); err != nil || iface == "" {
		t.Skipf("no default route to tell the netns apart (%q, %v)", iface, err)
	}
	// The main thread's netns, which /proc/net names, has a default route;
	// the worker's has none.
	empty := newNetns(t)
	var iface string
	if _, err := runInNetns(empty, zap.NewNop().Sugar(), func() ([]io.Closer, error) {
		var err error
		iface, err = findDefaultRouteInterface()
		return nil, err
	}); err != nil {
		t.Fatal(err)
	}
	if iface != "" {
		t.Errorf("default route in an empty netns: %q, want none", iface)
	}
}
