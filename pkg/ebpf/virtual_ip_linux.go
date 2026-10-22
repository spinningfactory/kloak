//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// vipHostVal matches C struct vip_host_val.
type vipHostVal struct {
	IP4 [4]byte
	IP6 [16]byte
}

// vipIPVal matches C struct vip_ip_val.
type vipIPVal struct {
	Host      [maxHostLen]byte
	HostLen   uint32
	Flags     uint32
	RetiredAt uint64
}

// vipFlagRetired is VIP_F_RETIRED in tls_uprobe.c.
const vipFlagRetired uint32 = 1

// vipConfigVal matches C struct vip_config_val.
type vipConfigVal struct {
	Net4  [4]byte // network byte order
	Mask4 [4]byte
}

// vipUpstreamSlots is VIP_UPSTREAM_SLOTS in helpers.h.
const vipUpstreamSlots = 4

// vipUpstreamVal matches C struct vip_upstream_val: the real addresses
// tc_dns_rewrite recorded for a fake IP.
type vipUpstreamVal struct {
	Slot [vipUpstreamSlots]vipUpstreamSlot
}

// vipUpstreamSlot matches C struct vip_upstream_slot.
type vipUpstreamSlot struct {
	IP4       [4]byte // all zero: empty slot
	_         uint32
	ExpiresAt uint64 // CLOCK_BOOTTIME nanoseconds
}

// virtualIPMaps are the maps pinned in virtual-ip mode.
var virtualIPMaps = []string{"vip_host_ip", "vip_ip_host", "vip_upstream"}

// vipConfig returns the vip_config value for the range r (IPv4).
func vipConfig(r netip.Prefix) vipConfigVal {
	var v vipConfigVal
	v.Net4 = r.Masked().Addr().As4()
	copy(v.Mask4[:], net.CIDRMask(r.Bits(), 32))
	return v
}

// attachVirtualIPRedirect enables the virtual IP data plane for range r:
// vip_config turns on tc_dns_rewrite, and the connect and getpeername
// hooks go on the kubepods cgroup at cgroupPath, which every pod's sockets
// are under. Attached there, they run before programs on the root cgroup (a
// CNI's socket load balancer), which then sees the real address.
func (m *TLSUprobeManager) attachVirtualIPRedirect(r netip.Prefix, cgroupPath string) error {
	if cgroupPath == "" {
		return errors.New("kubepods cgroup not found")
	}
	cfg := vipConfig(r)
	if err := m.objs.VipConfig.Update(uint32(0), &cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("writing vip_config: %w", err)
	}
	for _, p := range []struct {
		prog   *ebpf.Program
		attach ebpf.AttachType
	}{
		{m.objs.VipConnect4, ebpf.AttachCGroupInet4Connect},
		{m.objs.VipConnect6, ebpf.AttachCGroupInet6Connect},
		{m.objs.VipGetpeername4, ebpf.AttachCgroupInet4GetPeername},
		{m.objs.VipGetpeername6, ebpf.AttachCgroupInet6GetPeername},
	} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: p.attach, Program: p.prog})
		if err != nil {
			return fmt.Errorf("attaching %s to %s: %w", p.attach, cgroupPath, err)
		}
		m.linksMu.Lock()
		m.links = append(m.links, l)
		m.linksMu.Unlock()
	}
	return nil
}

// VirtualIPEnabled reports whether the manager runs in virtual-ip host
// resolution mode.
func (m *TLSUprobeManager) VirtualIPEnabled() bool {
	return m.virtualIPs != nil
}

// dnsRewriteAttach is tc_dns_rewrite attached in a pod's netns.
type dnsRewriteAttach struct {
	ino uint64
	// netns is kept open while attached, so its inode can't be reused by
	// another netns and wrongly look attached (see tcAttached).
	netns *os.File
	links []io.Closer
}

func (a *dnsRewriteAttach) close() {
	for _, l := range a.links {
		_ = l.Close()
	}
	_ = a.netns.Close()
}

// AttachPodDNSRewrite attaches tc_dns_rewrite, in virtual-ip mode, at tc
// ingress on the egress interfaces of a pod's network namespace, so that the
// pod is handed the fake IPs of the hosts it has secrets for
// (BindPodSecrets). pids are processes of the pod; the first one still
// running names the netns. The reconciler calls it as soon as the pod has
// its network, when only its sandbox runs, so that its containers start
// with the rewrite in place; an answer received before carries the real
// addresses (which the DNS snooping still attributes). It does nothing when
// already attached in the pod's current netns, in dns-snoop mode, or for a
// pod in the host network namespace, where the rewrite would hand fake IPs
// to node processes the connect redirect does not cover. A pod whose
// sandbox was recreated gets it again in its new netns.
func (m *TLSUprobeManager) AttachPodDNSRewrite(podUID, pod string, pids []int) error {
	if m.virtualIPs == nil {
		return nil
	}
	rootIno, err := netnsInode("/proc/1/ns/net")
	if err != nil {
		return err
	}
	var podNS *os.File
	var pid int
	for _, p := range pids {
		if f, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", p)); err == nil {
			podNS, pid = f, p
			break
		}
	}
	if podNS == nil {
		return fmt.Errorf("none of the %d processes of pod %s is running", len(pids), pod)
	}
	fi, err := podNS.Stat()
	if err != nil {
		_ = podNS.Close()
		return err
	}
	ino, err := statInode(fi)
	if err != nil || ino == rootIno {
		_ = podNS.Close()
		return err
	}

	m.dnsRewriteMu.Lock()
	defer m.dnsRewriteMu.Unlock()
	if cur := m.dnsRewrite[podUID]; cur != nil {
		if cur.ino == ino {
			_ = podNS.Close()
			return nil
		}
		// A new sandbox: the old netns is gone with its interfaces.
		delete(m.dnsRewrite, podUID)
		cur.close()
	}
	links, err := runInNetns(podNS, m.log, func() ([]io.Closer, error) {
		var links []io.Closer
		for _, name := range m.resolveEgressInterfaces(pid) {
			if name == "lo" {
				continue
			}
			iface, err := net.InterfaceByName(name)
			if err == nil {
				var l io.Closer
				if l, err = m.attachTCProgram(m.objs.TcDnsRewrite, iface.Index, true, podNS); err == nil {
					links = append(links, l)
					continue
				}
			}
			for _, l := range links {
				_ = l.Close()
			}
			return nil, fmt.Errorf("attaching the DNS rewrite to %s in pid %d netns: %w", name, pid, err)
		}
		return links, nil
	})
	if err == nil && len(links) == 0 &&
		!strings.EqualFold(m.egressInterface, "none") && !strings.EqualFold(m.egressInterface, "lo-only") {
		// No default route yet (CNI still setting up): the reconciler
		// retries.
		err = fmt.Errorf("no interface resolved in pid %d netns", pid)
	}
	if err != nil {
		_ = podNS.Close()
		if !m.dnsRewriteFailed[podUID] {
			m.dnsRewriteFailed[podUID] = true
			m.log.Warnw("failed to attach the DNS rewrite: the pod gets real addresses for watched hosts until it succeeds",
				"pod", pod, "pid", pid, "error", err)
		}
		return err
	}
	delete(m.dnsRewriteFailed, podUID)
	m.dnsRewrite[podUID] = &dnsRewriteAttach{ino: ino, netns: podNS, links: links}
	m.log.Infow("attached DNS rewrite to pod netns", "pod", pod, "pid", pid, "netns", ino, "interfaces", len(links))
	return nil
}

// DetachPodDNSRewrite removes the DNS rewrite of a pod that is gone, and
// releases its netns.
func (m *TLSUprobeManager) DetachPodDNSRewrite(podUID string) {
	m.dnsRewriteMu.Lock()
	a := m.dnsRewrite[podUID]
	delete(m.dnsRewrite, podUID)
	delete(m.dnsRewriteFailed, podUID)
	m.dnsRewriteMu.Unlock()
	if a != nil {
		a.close()
	}
}

// syncVipPodHost makes vip_pod_host hold exactly desired (vipPodHosts):
// pruning is what stops the rewrite for a pod that went away, or whose
// secrets no longer name a host. Stale entries go first, making room.
func syncVipPodHost(m *ebpf.Map, desired map[vipPodHostKey]struct{}, log *zap.SugaredLogger) {
	var stale []vipPodHostKey
	present := make(map[vipPodHostKey]struct{}, len(desired))
	var k vipPodHostKey
	var v uint8
	iter := m.Iterate()
	for iter.Next(&k, &v) {
		if _, ok := desired[k]; ok {
			present[k] = struct{}{}
		} else {
			stale = append(stale, k)
		}
	}
	if err := iter.Err(); err != nil {
		log.Errorw("error iterating BPF vip_pod_host", "error", err)
	}
	for i := range stale {
		if err := m.Delete(&stale[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Errorw("failed to remove a pod's virtual IP host", "error", err,
				"podIP", netip.AddrFrom16(stale[i].PodIP).Unmap().String())
		}
	}
	allowed := uint8(1)
	for key := range desired {
		if _, ok := present[key]; ok {
			continue
		}
		if err := m.Update(&key, &allowed, ebpf.UpdateAny); err != nil {
			// A missing entry leaves the pod the real addresses.
			log.Errorw("failed to grant the pod its hosts' virtual IPs", "error", err,
				"podIP", netip.AddrFrom16(key.PodIP).Unmap().String())
		}
	}
}

func netnsInode(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return statInode(fi)
}

func statInode(fi os.FileInfo) (uint64, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat %s: no inode", fi.Name())
	}
	return st.Ino, nil
}

// runInNetns runs fn on an OS thread switched into the network namespace
// ns, in a worker goroutine. If the thread can't be switched back, the
// worker exits with it still locked, so the Go runtime retires the thread
// instead of handing it to other goroutines (see attachTCEgress).
func runInNetns(ns *os.File, log *zap.SugaredLogger, fn func() ([]io.Closer, error)) ([]io.Closer, error) {
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, fmt.Errorf("opening self netns: %w", err)
	}
	defer func() { _ = self.Close() }()

	type result struct {
		links []io.Closer
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		usable := true
		defer func() {
			if usable {
				runtime.UnlockOSThread()
			}
		}()
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
			ch <- result{err: fmt.Errorf("setns: %w", err)}
			return
		}
		// Registered after the unlock: runs first.
		defer func() {
			if err := unix.Setns(int(self.Fd()), unix.CLONE_NEWNET); err != nil {
				log.Errorw("CRITICAL: failed to restore netns; retiring this worker goroutine's OS thread", "error", err)
				usable = false
			}
		}()
		links, err := fn()
		ch <- result{links: links, err: err}
	}()
	r := <-ch
	return r.links, r.err
}

// prepareVirtualIPPins marks the virtual IP maps of spec for pinning under
// pinPath, so loading spec reuses the maps a previous controller pinned
// there (and pins new ones otherwise). A pin whose layout no longer matches
// spec, left by another kloak version, is removed so the load recreates it
// instead of failing. Its hosts then get fresh fake IPs, mostly the same
// ones since allocation is derived from a hash of the host.
func prepareVirtualIPPins(spec *ebpf.CollectionSpec, pinPath string, log *zap.SugaredLogger) error {
	if err := requireBPFFS(pinPath); err != nil {
		return err
	}
	if err := os.MkdirAll(pinPath, 0o700); err != nil {
		return fmt.Errorf("creating pin directory: %w", err)
	}
	for _, name := range virtualIPMaps {
		ms, ok := spec.Maps[name]
		if !ok {
			return fmt.Errorf("map %s missing from the BPF objects", name)
		}
		ms.Pinning = ebpf.PinByName

		path := filepath.Join(pinPath, name)
		pinned, err := ebpf.LoadPinnedMap(path, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("opening pinned map %s: %w", path, err)
		}
		err = ms.Compatible(pinned)
		_ = pinned.Close()
		if err == nil {
			continue
		}
		log.Warnw("pinned virtual IP map does not match this version's layout, recreating it (its hosts get new fake IPs)",
			"path", path, "error", err)
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("removing incompatible pinned map %s: %w", path, err)
		}
	}
	return nil
}

// requireBPFFS checks that path, or its closest existing parent, is on a
// bpffs mount: a pin anywhere else fails, and a directory created on the
// wrong filesystem would be left behind.
func requireBPFFS(path string) error {
	dir := path
	for {
		var st unix.Statfs_t
		err := unix.Statfs(dir, &st)
		if err == nil {
			if uint32(st.Type) != unix.BPF_FS_MAGIC {
				return fmt.Errorf("%s is not on a bpffs mount (mount one at %s, or check the controller's /sys/fs/bpf volume)", dir, filepath.Dir(path))
			}
			return nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("statfs %s: %w", dir, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("statfs %s: %w", path, err)
		}
		dir = parent
	}
}

// RemoveVirtualIPPins deletes the virtual IP map pins a previous controller
// left in pinPath (empty means DefaultBPFPinPath) in virtual-ip mode, so that
// switching back to dns-snoop frees them. Only the node's controller should
// call it: it owns the pins, and removing them while it runs in virtual-ip
// mode would lose its reservations at the next restart.
func RemoveVirtualIPPins(pinPath string, log *zap.SugaredLogger) {
	if pinPath == "" {
		pinPath = DefaultBPFPinPath
	}
	for _, name := range virtualIPMaps {
		path := filepath.Join(pinPath, name)
		switch err := os.Remove(path); {
		case err == nil:
			log.Infow("removed virtual IP map pinned in virtual-ip mode", "path", path)
		case !errors.Is(err, os.ErrNotExist):
			log.Warnw("failed to remove virtual IP map pinned in virtual-ip mode", "path", path, "error", err)
		}
	}
	// Only succeeds if nothing else is pinned there.
	_ = os.Remove(pinPath)
}

// virtualIPAllocator keeps vip_ip_host and vip_host_ip in line with the
// watched hosts (planVirtualIPs), and clears vip_upstream of fake IPs that
// no longer lead to their host.
type virtualIPAllocator struct {
	hostIP   *ebpf.Map // vip_host_ip
	ipHost   *ebpf.Map // vip_ip_host
	upstream *ebpf.Map // vip_upstream; nil skips its cleanup
	prefix   netip.Prefix
	log      *zap.SugaredLogger
	// unallocated holds the hosts last reported as left without a fake IP,
	// so the error is logged when the set changes rather than every sync.
	unallocated []string
}

func newVirtualIPAllocator(objs *tlsuprobeObjects, prefix netip.Prefix, log *zap.SugaredLogger) *virtualIPAllocator {
	return &virtualIPAllocator{hostIP: objs.VipHostIp, ipHost: objs.VipIpHost, upstream: objs.VipUpstream, prefix: prefix, log: log}
}

// logRestored logs the reservations found in the pinned vip_ip_host, which
// a previous controller made.
func (a *virtualIPAllocator) logRestored() {
	existing, err := readVirtualIPs(a.ipHost)
	if err != nil {
		a.log.Errorw("failed to read pinned vip_ip_host", "error", err)
		return
	}
	for _, ip := range slices.SortedFunc(maps.Keys(existing), netip.Addr.Compare) {
		e := existing[ip]
		a.log.Infow("restored virtual IP", "host", e.Host, "ip", ip.String(), "retired", e.Retired)
	}
	a.log.Infow("virtual IP reservations restored from pinned map", "count", len(existing))
}

// sync makes the maps hold the reservations for hosts. A failed write is
// logged and retried at the next sync, since the plan is recomputed from
// what vip_ip_host actually holds.
func (a *virtualIPAllocator) sync(hosts map[string]struct{}, now time.Time) {
	existing, err := readVirtualIPs(a.ipHost)
	if err != nil {
		// Planning from a partial read could release live reservations.
		a.log.Errorw("failed to read vip_ip_host, skipping virtual IP sync", "error", err)
		return
	}
	currentHosts, err := readVirtualIPHosts(a.hostIP)
	if err != nil {
		a.log.Errorw("failed to read vip_host_ip, skipping virtual IP sync", "error", err)
		return
	}
	plan := planVirtualIPs(a.prefix, hosts, existing, now, int(a.ipHost.MaxEntries()))

	// Write order keeps every IP in vip_host_ip resolvable in vip_ip_host:
	// drop host -> IP entries that go away or change, then release
	// reservations (making room before new ones), then write reservations,
	// then the host -> IP side. vip_upstream is cleared of IPs released or
	// handed to another host before the new host -> IP entries let
	// tc_dns_rewrite record that host's addresses under them.
	for host, ip := range currentHosts {
		if want, ok := plan.Hosts[host]; ok && want == ip {
			continue
		}
		key := vipHostKey(host)
		if err := a.hostIP.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			a.log.Errorw("failed to delete vip_host_ip entry", "host", host, "error", err)
		}
	}
	for ip := range existing {
		if _, ok := plan.Entries[ip]; ok {
			continue
		}
		key := dnsIPKey{IP: ip.As16()}
		if err := a.ipHost.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			a.log.Errorw("failed to release virtual IP", "ip", ip.String(), "error", err)
		}
	}
	a.pruneUpstreams(existing, plan.Entries)
	for ip, e := range plan.Entries {
		val := vipIPValue(e)
		if old, ok := existing[ip]; ok && vipIPValue(old) == val {
			continue
		}
		key := dnsIPKey{IP: ip.As16()}
		if err := a.ipHost.Update(&key, &val, ebpf.UpdateAny); err != nil {
			a.log.Errorw("failed to write vip_ip_host entry", "ip", ip.String(), "host", e.Host, "error", err)
			// Without its reservation the IP must not be handed out.
			delete(plan.Hosts, e.Host)
		}
	}
	for host, ip := range plan.Hosts {
		if cur, ok := currentHosts[host]; ok && cur == ip {
			continue
		}
		key := vipHostKey(host)
		val := vipHostVal{IP4: ip.As4()}
		if err := a.hostIP.Update(&key, &val, ebpf.UpdateAny); err != nil {
			a.log.Errorw("failed to write vip_host_ip entry", "host", host, "ip", ip.String(), "error", err)
		}
	}

	for _, c := range plan.Allocated {
		a.log.Infow("allocated virtual IP", "host", c.Host, "ip", c.IP.String())
	}
	for _, c := range plan.Reactivated {
		a.log.Infow("reactivated virtual IP", "host", c.Host, "ip", c.IP.String())
	}
	for _, c := range plan.Retired {
		a.log.Infow("retired virtual IP (host no longer watched)", "host", c.Host, "ip", c.IP.String(),
			"reservedUntil", now.Add(virtualIPRetention).UTC().Format(time.RFC3339))
	}
	for _, c := range plan.Released {
		a.log.Infow("released virtual IP", "host", c.Host, "ip", c.IP.String(), "reason", c.Reason)
	}
	if !slices.Equal(plan.Unallocated, a.unallocated) {
		a.unallocated = plan.Unallocated
		if len(plan.Unallocated) > 0 {
			a.log.Errorw("virtual IP map is full, hosts left without a fake IP",
				"hosts", plan.Unallocated, "capacity", a.ipHost.MaxEntries())
		}
	}
}

// pruneUpstreams deletes the vip_upstream entries of fake IPs that are not
// reserved in plan, or reserved for another host than in existing: their
// addresses belong to a host the IP no longer leads to.
func (a *virtualIPAllocator) pruneUpstreams(existing, plan map[netip.Addr]vipEntry) {
	if a.upstream == nil {
		return
	}
	var stale []dnsIPKey
	var k dnsIPKey
	var v vipUpstreamVal
	iter := a.upstream.Iterate()
	for iter.Next(&k, &v) {
		ip := netip.AddrFrom16(k.IP).Unmap()
		if e, ok := plan[ip]; ok {
			if old, ok := existing[ip]; ok && old.Host == e.Host {
				continue
			}
		}
		stale = append(stale, k)
	}
	if err := iter.Err(); err != nil {
		a.log.Errorw("failed to read vip_upstream", "error", err)
	}
	for i := range stale {
		if err := a.upstream.Delete(&stale[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			a.log.Errorw("failed to delete vip_upstream entry", "ip", netip.AddrFrom16(stale[i].IP).Unmap().String(), "error", err)
		}
	}
}

// readVirtualIPs reads vip_ip_host.
func readVirtualIPs(m *ebpf.Map) (map[netip.Addr]vipEntry, error) {
	out := make(map[netip.Addr]vipEntry)
	var k dnsIPKey
	var v vipIPVal
	iter := m.Iterate()
	for iter.Next(&k, &v) {
		e := vipEntry{Host: vipHostString(v.Host, v.HostLen)}
		if v.Flags&vipFlagRetired != 0 {
			e.Retired = true
			e.RetiredAt = time.Unix(int64(v.RetiredAt), 0)
		}
		out[netip.AddrFrom16(k.IP).Unmap()] = e
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// readVirtualIPHosts reads the IPv4 side of vip_host_ip.
func readVirtualIPHosts(m *ebpf.Map) (map[string]netip.Addr, error) {
	out := make(map[string]netip.Addr)
	var k watchedHostKey
	var v vipHostVal
	iter := m.Iterate()
	for iter.Next(&k, &v) {
		out[vipHostString(k.Host, maxHostLen)] = netip.AddrFrom4(v.IP4)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func vipHostKey(host string) watchedHostKey {
	var k watchedHostKey
	copy(k.Host[:], host)
	return k
}

func vipIPValue(e vipEntry) vipIPVal {
	var v vipIPVal
	n := copy(v.Host[:], e.Host)
	v.HostLen = uint32(n)
	if e.Retired {
		v.Flags = vipFlagRetired
		v.RetiredAt = uint64(e.RetiredAt.Unix())
	}
	return v
}

// vipHostString returns the host in a zero-padded host buffer, at most n
// bytes long.
func vipHostString(b [maxHostLen]byte, n uint32) string {
	s := b[:min(int(n), len(b))]
	for i, c := range s {
		if c == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}
