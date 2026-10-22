package controller

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
	nrilog "github.com/containerd/nri/pkg/log"
	"github.com/containerd/nri/pkg/stub"
	"go.uber.org/zap"

	"github.com/spinningfactory/kloak/pkg/logging"
)

const (
	// DefaultNRISocket is where containerd (2.0+) and CRI-O (1.30+) serve
	// NRI by default.
	DefaultNRISocket = "/var/run/nri/nri.sock"

	nriPluginName = "kloak"
	// nriPluginIdx orders kloak among NRI plugins. It makes no container
	// adjustments, so the position only matters for when it is called.
	nriPluginIdx = "50"
)

// SandboxPreparer prepares a pod sandbox the container runtime is creating
// (Reconciler.PrepareSandbox).
type SandboxPreparer interface {
	PrepareSandbox(ctx context.Context, sb *Sandbox) bool
}

// NRIPlugin hooks kloak into the container runtime through NRI (the Node
// Resource Interface of containerd and CRI-O). The runtime calls it while
// it creates each pod sandbox, and again before each container, and waits
// for it: kloak attaches the virtual IP DNS rewrite then (PrepareSandbox),
// before any container of the pod resolves a name. Without NRI (a runtime
// without it, NRI disabled, or the socket not mounted), the Reconciler
// attaches the rewrite by polling Pending pods instead.
//
// The plugin never fails a runtime request: an error would fail the pod's
// sandbox or container. A request taking longer than the runtime's timeout
// (2 s by default) disconnects the plugin, which reconnects.
type NRIPlugin struct {
	Preparer   SandboxPreparer
	SocketPath string
	// HostRoot is the host's root filesystem as this process sees it: the
	// runtime reports network namespace paths in the host's mount
	// namespace. "" means /proc/1/root (with hostPID).
	HostRoot string
	Log      *zap.SugaredLogger

	// Reconnect delays: after the runtime's connection closed, and while no
	// runtime serves NRI at SocketPath. Zero means the defaults.
	RetryAfterClose  time.Duration
	RetryUnavailable time.Duration

	mu       sync.Mutex
	prepared map[string]bool // sandbox IDs PrepareSandbox reported ready
}

// Run serves NRI until ctx is done, reconnecting when the runtime's
// connection closes. It returns nil: NRI is optional, and the manager stops
// when a runnable returns an error.
func (p *NRIPlugin) Run(ctx context.Context) error {
	useNRILogger(p.Log)
	afterClose, unavailable := p.RetryAfterClose, p.RetryUnavailable
	if afterClose == 0 {
		afterClose = time.Second
	}
	if unavailable == 0 {
		unavailable = 30 * time.Second
	}
	reported := false
	for {
		closed, err := p.connect(ctx)
		delay := afterClose
		switch {
		case err != nil:
			if !reported {
				reported = true
				p.Log.Infow("NRI not available: the DNS rewrite is attached by polling pending pods, which leaves a short window at pod start; retrying in the background",
					"socket", p.SocketPath, "error", err)
			}
			delay = unavailable
		default:
			reported = false
			select {
			case <-closed:
				p.Log.Warnw("NRI connection to the container runtime closed, reconnecting", "socket", p.SocketPath)
			case <-ctx.Done():
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

// connect registers with the runtime at SocketPath. The returned channel
// is closed when the connection goes down.
func (p *NRIPlugin) connect(ctx context.Context) (<-chan struct{}, error) {
	closed := make(chan struct{})
	var once sync.Once
	s, err := stub.New(&nriHandlers{p: p},
		stub.WithPluginName(nriPluginName),
		stub.WithPluginIdx(nriPluginIdx),
		stub.WithSocketPath(p.SocketPath),
		stub.WithOnClose(func() { once.Do(func() { close(closed) }) }),
	)
	if err != nil {
		return nil, err
	}
	if err := s.Start(ctx); err != nil {
		return nil, err
	}
	go func() {
		select {
		case <-ctx.Done():
			s.Stop()
		case <-closed:
		}
	}()
	return closed, nil
}

// prepare runs PrepareSandbox for pod unless it already reported the
// sandbox ready.
func (p *NRIPlugin) prepare(ctx context.Context, pod *api.PodSandbox) {
	p.mu.Lock()
	done := p.prepared[pod.GetId()]
	p.mu.Unlock()
	if done {
		return
	}
	sb := sandboxFromNRI(pod, p.HostRoot)
	logging.Tracew(p.Log, "NRI sandbox", "sandbox", sb.ID, "pod", sb.Namespace+"/"+sb.Name,
		"kloak", sb.Annotations[AnnotationEnabled], "netns", sb.NetnsPath, "pid", pod.GetPid(), "ips", sb.IPs,
		"namespaces", pod.GetLinux().GetNamespaces(), "annotations", len(sb.Annotations))
	if !p.Preparer.PrepareSandbox(ctx, sb) {
		return
	}
	p.mu.Lock()
	if p.prepared == nil {
		p.prepared = make(map[string]bool)
	}
	p.prepared[pod.GetId()] = true
	p.mu.Unlock()
}

func (p *NRIPlugin) forget(pod *api.PodSandbox) {
	p.mu.Lock()
	delete(p.prepared, pod.GetId())
	p.mu.Unlock()
}

// keepOnly forgets the prepared sandboxes not in pods, the runtime's
// current ones: those removed while the plugin was not connected.
func (p *NRIPlugin) keepOnly(pods []*api.PodSandbox) {
	current := make(map[string]bool, len(pods))
	for _, pod := range pods {
		current[pod.GetId()] = true
	}
	p.mu.Lock()
	for id := range p.prepared {
		if !current[id] {
			delete(p.prepared, id)
		}
	}
	p.mu.Unlock()
}

// sandboxFromNRI converts the runtime's view of a sandbox. Its network
// namespace is its process's when the runtime reports the process, or else
// the bind mount in its namespace list (such as /var/run/netns/cni-…),
// reached through hostRoot. A sandbox listing no network namespace of its
// own is in the host's.
func sandboxFromNRI(pod *api.PodSandbox, hostRoot string) *Sandbox {
	if hostRoot == "" {
		hostRoot = "/proc/1/root"
	}
	sb := &Sandbox{
		ID:          pod.GetId(),
		UID:         pod.GetUid(),
		Namespace:   pod.GetNamespace(),
		Name:        pod.GetName(),
		Annotations: pod.GetAnnotations(),
	}
	for _, ns := range pod.GetLinux().GetNamespaces() {
		if ns.GetType() != "network" {
			continue
		}
		switch {
		case pod.GetPid() > 0:
			sb.NetnsPath = fmt.Sprintf("/proc/%d/ns/net", pod.GetPid())
		case ns.GetPath() != "":
			sb.NetnsPath = inRoot(hostRoot, ns.GetPath())
		}
	}
	for _, s := range pod.GetIps() {
		if a, err := netip.ParseAddr(s); err == nil {
			sb.IPs = append(sb.IPs, a.Unmap())
		}
	}
	return sb
}

// inRoot returns path, an absolute path of the filesystem whose root this
// process sees at root (such as /proc/1/root), with its symlinks resolved
// in that filesystem: an absolute link target is relative to its root, not
// this process's (on most hosts /var/run links to /run, which the
// controller's container does not share). A missing component is kept as
// is, for opening to fail on; so is the path past too many links.
func inRoot(root, path string) string {
	resolved := "/"
	rest := strings.Split(path, "/")
	for links := 0; len(rest) > 0; {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, c)
		target, err := os.Readlink(filepath.Join(root, next))
		if err != nil || links >= 40 {
			resolved = next
			continue
		}
		links++
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return filepath.Join(root, resolved)
}

// nriHandlers are the NRI events kloak subscribes to.
type nriHandlers struct{ p *NRIPlugin }

func (h *nriHandlers) Configure(_ context.Context, _, runtime, version string) (api.EventMask, error) {
	h.p.Log.Infow("connected to the container runtime through NRI: the DNS rewrite is attached while each pod sandbox is created",
		"runtime", runtime, "version", version, "socket", h.p.SocketPath)
	return 0, nil // the events of the methods below
}

// Synchronize lists the runtime's sandboxes when the plugin connects.
func (h *nriHandlers) Synchronize(_ context.Context, pods []*api.PodSandbox, _ []*api.Container) ([]*api.ContainerUpdate, error) {
	h.p.keepOnly(pods)
	return nil, nil
}

func (h *nriHandlers) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	h.p.prepare(ctx, pod)
	return nil
}

// CreateContainer covers a sandbox created before the plugin connected, or
// whose pod the reconciler could not see yet.
func (h *nriHandlers) CreateContainer(ctx context.Context, pod *api.PodSandbox, _ *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	h.p.prepare(ctx, pod)
	return nil, nil, nil
}

func (h *nriHandlers) RemovePodSandbox(_ context.Context, pod *api.PodSandbox) error {
	h.p.forget(pod)
	return nil
}

var nriLogOnce sync.Once

// useNRILogger sends the NRI library's logs to log. Its logger is
// process-wide: only the first call sets it, before any use.
func useNRILogger(log *zap.SugaredLogger) {
	nriLogOnce.Do(func() {
		nrilog.Set(nriLogger{log.Desugar().WithOptions(zap.AddCallerSkip(1)).Sugar()})
	})
}

// nriLogger sends the NRI library's logs to the controller's logger.
type nriLogger struct{ l *zap.SugaredLogger }

func (n nriLogger) Debugf(_ context.Context, f string, a ...interface{}) { n.l.Debugf("nri: "+f, a...) }
func (n nriLogger) Infof(_ context.Context, f string, a ...interface{})  { n.l.Debugf("nri: "+f, a...) }
func (n nriLogger) Warnf(_ context.Context, f string, a ...interface{})  { n.l.Warnf("nri: "+f, a...) }
func (n nriLogger) Errorf(_ context.Context, f string, a ...interface{}) { n.l.Errorf("nri: "+f, a...) }
