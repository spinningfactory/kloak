//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/cilium/ebpf"
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

// virtualIPMaps are the maps pinned in virtual-ip mode.
var virtualIPMaps = []string{"vip_host_ip", "vip_ip_host"}

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
// watched hosts (planVirtualIPs).
type virtualIPAllocator struct {
	hostIP *ebpf.Map // vip_host_ip
	ipHost *ebpf.Map // vip_ip_host
	prefix netip.Prefix
	log    *zap.SugaredLogger
	// unallocated holds the hosts last reported as left without a fake IP,
	// so the error is logged when the set changes rather than every sync.
	unallocated []string
}

func newVirtualIPAllocator(objs *tlsuprobeObjects, prefix netip.Prefix, log *zap.SugaredLogger) *virtualIPAllocator {
	return &virtualIPAllocator{hostIP: objs.VipHostIp, ipHost: objs.VipIpHost, prefix: prefix, log: log}
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
	// then the host -> IP side.
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
