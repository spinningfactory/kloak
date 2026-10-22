package controller

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/adaptation"
	"github.com/containerd/nri/pkg/api"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSandboxFromNRI(t *testing.T) {
	netns := &api.LinuxPodSandbox{Namespaces: []*api.LinuxNamespace{
		{Type: "ipc"},
		{Type: "network", Path: "/var/run/netns/cni-1234"},
	}}
	for _, c := range []struct {
		name string
		pod  *api.PodSandbox
		want Sandbox
	}{
		{"the sandbox process's network namespace", &api.PodSandbox{
			Id: "sb1", Uid: "uid1", Namespace: "ns", Name: "app",
			Annotations: map[string]string{AnnotationEnabled: "true"},
			Linux:       netns, Pid: 42,
			Ips: []string{"10.42.0.7", "::ffff:10.42.0.8", "fd42::7", "bogus"},
		}, Sandbox{
			ID: "sb1", UID: "uid1", Namespace: "ns", Name: "app",
			Annotations: map[string]string{AnnotationEnabled: "true"},
			NetnsPath:   "/proc/42/ns/net",
			IPs:         []netip.Addr{netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("10.42.0.8"), netip.MustParseAddr("fd42::7")},
		}},
		{"no process: the network namespace's path, in the host's root", &api.PodSandbox{
			Id: "sb2", Linux: netns,
		}, Sandbox{ID: "sb2", NetnsPath: "/host/var/run/netns/cni-1234"}},
		// The host's network namespace (hostNetwork pods) is not listed.
		{"host network", &api.PodSandbox{
			Id: "sb3", Pid: 42, Linux: &api.LinuxPodSandbox{Namespaces: []*api.LinuxNamespace{{Type: "ipc"}}},
		}, Sandbox{ID: "sb3"}},
		{"nothing reported", &api.PodSandbox{Id: "sb4"}, Sandbox{ID: "sb4"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := sandboxFromNRI(c.pod, "/host"); !reflect.DeepEqual(*got, c.want) {
				t.Errorf("got %+v\nwant %+v", got, c.want)
			}
		})
	}
	if got := sandboxFromNRI(&api.PodSandbox{Linux: netns}, "").NetnsPath; got != "/proc/1/root/var/run/netns/cni-1234" {
		t.Errorf("default host root: %s", got)
	}
}

func TestInRoot(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"run/netns", "srv/a"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"var/run":  "/run",     // absolute: in root, not in this process's /
		"srv/b":    "a",        // relative
		"srv/up":   "../run",   // relative, upwards
		"loop":     "/loop",    // a cycle
		"var/lock": "/no/such", // dangling
	} {
		p := filepath.Join(root, link)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	for in, want := range map[string]string{
		"/var/run/netns/cni-1": "/run/netns/cni-1",
		"/srv/b/x":             "/srv/a/x",
		"/srv/up/netns":        "/run/netns",
		"/run/./netns/../x":    "/run/x",
		"/var/lock/x":          "/no/such/x",
		"/missing/x":           "/missing/x",
	} {
		if got := inRoot(root, in); got != filepath.Join(root, want) {
			t.Errorf("inRoot(%s) = %s, want %s", in, got, filepath.Join(root, want))
		}
	}
	// A cycle ends after the link budget, inside root.
	if got := inRoot(root, "/loop/x"); !strings.HasPrefix(got, root) {
		t.Errorf("cycle: %s", got)
	}
}

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	return s
}

func testPod(uid string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: types.UID(uid)}}
}

func TestSandboxPod(t *testing.T) {
	sb := Sandbox{UID: "uid-new", Namespace: "ns", Name: "app"}
	newer := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(testPod("uid-new")).Build()
	older := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(testPod("uid-old")).Build()
	empty := fake.NewClientBuilder().WithScheme(testScheme()).Build()

	for _, c := range []struct {
		name   string
		cache  client.Client
		api    client.Reader
		wantOK bool
	}{
		{"in the cache", newer, nil, true},
		// The cache still has the pod's predecessor of the same name.
		{"stale cache, read from the API", older, newer, true},
		{"not in the cache, read from the API", empty, newer, true},
		{"not in the cache, no API reader", empty, nil, false},
		{"another pod of that name in the API", empty, older, false},
		{"nowhere", empty, empty, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := NewReconciler(c.cache, zap.NewNop().Sugar(), testScheme(), nil, "", "")
			r.APIReader = c.api
			pod, err := r.sandboxPod(context.Background(), &sb)
			if (err == nil) != c.wantOK {
				t.Fatalf("pod %v, error %v; want ok %v", pod, err, c.wantOK)
			}
			if err == nil && pod.UID != "uid-new" {
				t.Errorf("got pod %s", pod.UID)
			}
		})
	}
}

func TestPrepareSandboxSkips(t *testing.T) {
	// Without the virtual-ip data plane (here: no eBPF manager), nothing
	// is prepared and the pod is not looked up.
	c := fake.NewClientBuilder().WithScheme(testScheme()).Build()
	r := NewReconciler(c, zap.NewNop().Sugar(), testScheme(), nil, "", "")
	sb := Sandbox{UID: "u", Namespace: "ns", Name: "app", NetnsPath: "/proc/1/ns/net",
		Annotations: map[string]string{AnnotationEnabled: "true"}}
	if r.PrepareSandbox(context.Background(), &sb) {
		t.Error("prepared without the virtual-ip data plane")
	}
	if n := r.GetTrackedPodCount(); n != 0 {
		t.Errorf("%d pods tracked", n)
	}
}

// fakePreparer records the sandboxes it is asked to prepare; it reports
// ready the sandbox IDs in ready.
type fakePreparer struct {
	mu    sync.Mutex
	ready map[string]bool
	calls []Sandbox
}

func (f *fakePreparer) PrepareSandbox(_ context.Context, sb *Sandbox) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, *sb)
	return f.ready[sb.ID]
}

func (f *fakePreparer) count(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.ID == id {
			n++
		}
	}
	return n
}

// startNRIRuntime serves NRI at sock, as a container runtime does, with
// NRI's own runtime side.
func startNRIRuntime(t *testing.T, sock string) *adaptation.Adaptation {
	t.Helper()
	// NRI's logger is process-wide, shared with the runtime side here: set
	// it before the runtime uses it.
	useNRILogger(zap.NewNop().Sugar())
	dir := t.TempDir()
	rt, err := adaptation.New("fake-runtime", "v0",
		func(ctx context.Context, cb adaptation.SyncCB) error {
			_, err := cb(ctx, nil, nil)
			return err
		},
		func(context.Context, []*adaptation.ContainerUpdate) ([]*adaptation.ContainerUpdate, error) {
			return nil, nil
		},
		adaptation.WithSocketPath(sock),
		adaptation.WithPluginPath(filepath.Join(dir, "plugins")),
		adaptation.WithPluginConfigPath(filepath.Join(dir, "conf")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(); err != nil {
		t.Fatal(err)
	}
	return rt
}

func sandbox(id string) *api.PodSandbox {
	return &api.PodSandbox{
		Id: id, Uid: "uid-" + id, Namespace: "ns", Name: id,
		Annotations: map[string]string{AnnotationEnabled: "true"},
		Linux:       &api.LinuxPodSandbox{Namespaces: []*api.LinuxNamespace{{Type: "network", Path: "/var/run/netns/" + id}}},
		Ips:         []string{"10.42.0.7"},
	}
}

// waitRegistered sends RunPodSandbox for a probe sandbox until the plugin
// sees it: the runtime only calls plugins that completed registration.
func waitRegistered(t *testing.T, rt *adaptation.Adaptation, prep *fakePreparer, probe string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for prep.count(probe) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the plugin did not register with the runtime")
		}
		if err := rt.RunPodSandbox(context.Background(), &adaptation.RunPodSandboxRequest{Pod: sandbox(probe)}); err != nil {
			t.Fatalf("RunPodSandbox: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// socketProxy forwards the connections made to its socket to a runtime's
// socket. Closing it drops them, as the runtime's process exiting does (the
// NRI runtime side leaves external plugins connected when stopped).
type socketProxy struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func startSocketProxy(t *testing.T, path, target string) *socketProxy {
	t.Helper()
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	p := &socketProxy{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("unix", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
	return p
}

func (p *socketProxy) close() {
	_ = p.ln.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
}

// TestNRIPlugin runs the plugin against NRI's runtime side over a unix
// socket: the runtime's sandbox and container requests reach
// PrepareSandbox synchronously, a prepared sandbox is not prepared again
// until removed, no request fails, and the plugin reconnects to a
// restarted runtime.
func TestNRIPlugin(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nri.sock")
	rt := startNRIRuntime(t, filepath.Join(dir, "runtime-1.sock"))
	proxy := startSocketProxy(t, sock, filepath.Join(dir, "runtime-1.sock"))
	prep := &fakePreparer{ready: map[string]bool{"ready": true}}
	p := &NRIPlugin{Preparer: prep, SocketPath: sock, HostRoot: "/host", Log: zap.NewNop().Sugar(),
		RetryAfterClose: 10 * time.Millisecond, RetryUnavailable: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	waitRegistered(t, rt, prep, "probe")
	bg := context.Background()

	// Synchronous: prepared by the time RunPodSandbox returns.
	if err := rt.RunPodSandbox(bg, &adaptation.RunPodSandboxRequest{Pod: sandbox("ready")}); err != nil {
		t.Fatal(err)
	}
	if n := prep.count("ready"); n != 1 {
		t.Fatalf("RunPodSandbox prepared the sandbox %d times, want 1", n)
	}
	prep.mu.Lock()
	got := prep.calls[len(prep.calls)-1]
	prep.mu.Unlock()
	if got.NetnsPath != "/host/var/run/netns/ready" || got.UID != "uid-ready" || len(got.IPs) != 1 {
		t.Errorf("sandbox passed: %+v", got)
	}
	ctr := func(id string) *adaptation.CreateContainerRequest {
		return &adaptation.CreateContainerRequest{Pod: sandbox(id), Container: &api.Container{Id: id + "-c", PodSandboxId: id, Name: "c"}}
	}
	if _, err := rt.CreateContainer(bg, ctr("ready")); err != nil {
		t.Fatal(err)
	}
	if n := prep.count("ready"); n != 1 {
		t.Errorf("a container of a prepared sandbox prepared it again (%d calls)", n)
	}

	// Not prepared at sandbox creation (the pod was not found, say): each
	// container retries, and nothing fails.
	if err := rt.RunPodSandbox(bg, &adaptation.RunPodSandboxRequest{Pod: sandbox("late")}); err != nil {
		t.Fatalf("RunPodSandbox failed for a sandbox not prepared: %v", err)
	}
	for range 2 {
		if _, err := rt.CreateContainer(bg, ctr("late")); err != nil {
			t.Fatal(err)
		}
	}
	if n := prep.count("late"); n != 3 {
		t.Errorf("sandbox not prepared: %d calls, want 3", n)
	}

	// A removed sandbox is forgotten.
	if err := rt.RemovePodSandbox(bg, &adaptation.RemovePodSandboxRequest{Pod: sandbox("ready")}); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.CreateContainer(bg, ctr("ready")); err != nil {
		t.Fatal(err)
	}
	if n := prep.count("ready"); n != 2 {
		t.Errorf("after removal: %d calls, want 2", n)
	}

	// The runtime restarts: the plugin connects to the new one, which lists
	// no sandbox, so "ready" (removed meanwhile) is prepared again.
	proxy.close()
	rt.Stop()
	rt = startNRIRuntime(t, filepath.Join(dir, "runtime-2.sock"))
	defer rt.Stop()
	proxy = startSocketProxy(t, sock, filepath.Join(dir, "runtime-2.sock"))
	defer proxy.close()
	waitRegistered(t, rt, prep, "probe-2")
	if _, err := rt.CreateContainer(bg, ctr("ready")); err != nil {
		t.Fatal(err)
	}
	if n := prep.count("ready"); n != 3 {
		t.Errorf("after the runtime restarted: %d calls, want 3", n)
	}
}

func TestNRIPluginWithoutRuntime(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	p := &NRIPlugin{Preparer: &fakePreparer{}, SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
		Log: zap.New(core).Sugar(), RetryUnavailable: 5 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run returned %v: the manager would stop", err)
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("Run returned before its context was done")
	}
	// Retried many times, reported once.
	if n := logs.FilterMessageSnippet("NRI not available").Len(); n != 1 {
		t.Errorf("logged %d times that NRI is not available, want once", n)
	}
}
