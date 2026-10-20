package ebpf

import (
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"maps"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// HostResolutionMode selects how the data plane works out which host a TLS
// connection is going to (spinningfactory/kloak#327).
type HostResolutionMode string

const (
	// HostResolutionDNSSnoop reads DNS answers as pods receive them
	// (udp_recvmsg) and keeps a node-wide IP -> host map. The default.
	HostResolutionDNSSnoop HostResolutionMode = "dns-snoop"
	// HostResolutionVirtualIP gives every watched host a stable fake IP
	// from a reserved range, kept in maps pinned in bpffs. Experimental:
	// the fake IPs are allocated, but DNS answers are not rewritten to them
	// yet, so the dns-snoop path still decides the host.
	HostResolutionVirtualIP HostResolutionMode = "virtual-ip"
)

// ParseHostResolutionMode validates a --host-resolution value.
func ParseHostResolutionMode(s string) (HostResolutionMode, error) {
	switch HostResolutionMode(strings.ToLower(strings.TrimSpace(s))) {
	case "", HostResolutionDNSSnoop:
		return HostResolutionDNSSnoop, nil
	case HostResolutionVirtualIP:
		return HostResolutionVirtualIP, nil
	default:
		return "", fmt.Errorf("invalid host resolution mode %q (want dns-snoop or virtual-ip)", s)
	}
}

// DefaultVirtualIPRange is the default range fake IPs come from. RFC 2544
// reserves 198.18.0.0/15 for benchmarking, so it should never be routed.
const DefaultVirtualIPRange = "198.18.0.0/15"

// DefaultBPFPinPath is the bpffs directory kloak pins its maps in.
const DefaultBPFPinPath = "/sys/fs/bpf/kloak"

// maxVirtualIPPrefixLen is the smallest range accepted: a /19 holds twice
// vip_ip_host's 4096 entries, so probing for a free address stays short and
// the map, not the range, is what fills up first.
const maxVirtualIPPrefixLen = 19

// virtualIPRetention is how long a fake IP stays reserved for a host that is
// no longer watched. Apps cache DNS answers, so handing the IP to another
// host right away could send that app's traffic to the wrong host.
const virtualIPRetention = 24 * time.Hour

// ParseVirtualIPRange validates a --virtual-ip-range value: an IPv4 network
// address of at least a /19.
func ParseVirtualIPRange(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid virtual IP range %q: %w", s, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("virtual IP range %q is not IPv4", s)
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("virtual IP range %q has host bits set (did you mean %s?)", s, p.Masked())
	}
	if p.Bits() > maxVirtualIPPrefixLen {
		return netip.Prefix{}, fmt.Errorf("virtual IP range %q is too small (want /%d or larger)", s, maxVirtualIPPrefixLen)
	}
	return p, nil
}

// HostResolutionConfig is the host resolution setup of a TLSUprobeManager.
// It is passed at construction rather than through a setter because
// whether the virtual IP maps are pinned is decided when the BPF objects
// are loaded.
type HostResolutionConfig struct {
	// Mode is the host resolution mode. Empty means dns-snoop.
	Mode HostResolutionMode
	// VirtualIPRange is the IPv4 range fake IPs come from (virtual-ip mode
	// only; see ParseVirtualIPRange).
	VirtualIPRange netip.Prefix
	// PinPath is the bpffs directory the virtual IP maps are pinned in.
	// Empty means DefaultBPFPinPath.
	PinPath string
}

func (c HostResolutionConfig) virtualIP() bool {
	return c.Mode == HostResolutionVirtualIP
}

func (c HostResolutionConfig) pinPath() string {
	if c.PinPath == "" {
		return DefaultBPFPinPath
	}
	return c.PinPath
}

func (c HostResolutionConfig) validate() error {
	switch c.Mode {
	case "", HostResolutionDNSSnoop:
		return nil
	case HostResolutionVirtualIP:
		if !c.VirtualIPRange.IsValid() {
			return fmt.Errorf("virtual-ip host resolution needs a virtual IP range")
		}
		_, err := ParseVirtualIPRange(c.VirtualIPRange.String())
		return err
	default:
		return fmt.Errorf("invalid host resolution mode %q", c.Mode)
	}
}

// ReservedRange is an address range the virtual IP range must not overlap,
// with where it came from.
type ReservedRange struct {
	Prefix netip.Prefix
	Source string
}

// CheckVirtualIPRange returns an error naming every reserved range that
// overlaps r. A fake IP inside a real range would be ambiguous, and when the
// connect redirect is not in place (for example while the controller
// restarts) traffic to it would reach whatever that range routes to. Default
// routes are ignored, since they overlap everything.
func CheckVirtualIPRange(r netip.Prefix, reserved []ReservedRange) error {
	var conflicts []string
	for _, rr := range reserved {
		if rr.Prefix.Bits() == 0 || !rr.Prefix.Overlaps(r) {
			continue
		}
		conflicts = append(conflicts, fmt.Sprintf("%s (%s)", rr.Prefix, rr.Source))
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("virtual IP range %s overlaps %s; choose another range with --virtual-ip-range",
			r, strings.Join(conflicts, ", "))
	}
	return nil
}

// HostRoutes returns the IPv4 routes of the network namespace of the
// process whose procfs directory is procDir (for example "/proc/1" for the
// host, with hostPID), default route included.
func HostRoutes(procDir string) ([]ReservedRange, error) {
	path := filepath.Join(procDir, "net", "route")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var out []ReservedRange
	for _, rt := range parseRoutes(data) {
		out = append(out, ReservedRange{Prefix: rt.dst, Source: "node route via " + rt.iface})
	}
	return out, nil
}

type route struct {
	iface string
	dst   netip.Prefix
}

// parseRoutes reads the destination and mask of every row of a
// /proc/net/route body (see parseDefaultRouteInterface for the format).
// The kernel prints each address as the hex of its in-memory __be32, so
// the bytes are decoded in native order. Rows that don't parse, or whose
// mask is not contiguous, are skipped.
func parseRoutes(data []byte) []route {
	var out []route
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue // header row
		}
		fields := strings.Fields(line)
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if len(fields) < 8 {
			continue
		}
		dst, ok := parseRouteAddr(fields[1])
		if !ok {
			continue
		}
		mask, ok := parseRouteAddr(fields[7])
		if !ok {
			continue
		}
		m := binary.BigEndian.Uint32(mask.AsSlice())
		ones := bits.LeadingZeros32(^m)
		if bits.OnesCount32(m) != ones {
			continue
		}
		out = append(out, route{iface: fields[0], dst: netip.PrefixFrom(dst, ones).Masked()})
	}
	return out
}

func parseRouteAddr(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, false
	}
	var a [4]byte
	binary.NativeEndian.PutUint32(a[:], binary.BigEndian.Uint32(b))
	return netip.AddrFrom4(a), true
}

// vipEntry is one fake IP reservation, the semantic form of a vip_ip_host
// entry. A retired entry belongs to a host that is no longer watched and is
// kept until virtualIPRetention has passed.
type vipEntry struct {
	Host      string
	Retired   bool
	RetiredAt time.Time // zero unless Retired
}

// vipChange describes one reservation planVirtualIPs adds, changes or drops.
type vipChange struct {
	IP     netip.Addr
	Host   string
	Reason string // set on releases
}

// vipPlan is the content vip_ip_host and vip_host_ip should have, and how it
// differs from what they had.
type vipPlan struct {
	// Entries is the desired vip_ip_host: every reservation, active or
	// retired.
	Entries map[netip.Addr]vipEntry
	// Hosts is the desired vip_host_ip: the active fake IP of each watched
	// host that has one.
	Hosts map[string]netip.Addr

	Allocated   []vipChange
	Reactivated []vipChange
	Retired     []vipChange
	Released    []vipChange
	// Unallocated lists watched hosts left without a fake IP because
	// capacity is taken by active reservations.
	Unallocated []string
}

// planVirtualIPs works out the reservations for the watched hosts, given
// the existing ones (read back from the pinned vip_ip_host) and room for
// capacity entries:
//
//   - an existing reservation is kept: a host keeps its fake IP for as long
//     as it is watched, and a retired host that is watched again gets its
//     old IP back;
//   - a new host gets the first free address at or after
//     fnv1a64(host) mod size(r), skipping the first and last address of r
//     and every address ending in .0 or .255. Hosts are allocated in
//     sorted order, so the result does not depend on map iteration order;
//   - a reservation whose host is no longer watched is retired, and
//     released once virtualIPRetention has passed;
//   - reservations outside r (the range was changed) are released;
//   - when capacity is reached the oldest retired reservation is evicted;
//     if there is none, the host is left without a fake IP.
func planVirtualIPs(r netip.Prefix, hosts map[string]struct{}, existing map[netip.Addr]vipEntry, now time.Time, capacity int) vipPlan {
	plan := vipPlan{
		Entries: make(map[netip.Addr]vipEntry, len(existing)+len(hosts)),
		Hosts:   make(map[string]netip.Addr, len(hosts)),
	}

	// Keep the reservations that are still valid, grouped by host.
	byHost := make(map[string][]netip.Addr)
	for _, ip := range slices.SortedFunc(maps.Keys(existing), netip.Addr.Compare) {
		e := existing[ip]
		reason := ""
		switch {
		case e.Host == "":
			reason = "entry has no host"
		case !r.Contains(ip):
			reason = "outside the virtual IP range"
		case e.Retired && now.Sub(e.RetiredAt) >= virtualIPRetention:
			reason = "retention period over"
		}
		if reason != "" {
			plan.Released = append(plan.Released, vipChange{IP: ip, Host: e.Host, Reason: reason})
			continue
		}
		plan.Entries[ip] = e
		byHost[e.Host] = append(byHost[e.Host], ip)
	}

	// Each watched host keeps one active IP: its active one, or else its
	// retired one, reactivated. Every other IP of a host is retired.
	for _, host := range slices.Sorted(maps.Keys(byHost)) {
		ips := byHost[host]
		_, watched := hosts[host]
		keep := netip.Addr{}
		if watched {
			keep = ips[0]
			for _, ip := range ips {
				if !plan.Entries[ip].Retired {
					keep = ip
					break
				}
			}
			plan.Hosts[host] = keep
			if e := plan.Entries[keep]; e.Retired {
				plan.Entries[keep] = vipEntry{Host: host}
				plan.Reactivated = append(plan.Reactivated, vipChange{IP: keep, Host: host})
			}
		}
		for _, ip := range ips {
			if ip == keep || plan.Entries[ip].Retired {
				continue
			}
			plan.Entries[ip] = vipEntry{Host: host, Retired: true, RetiredAt: now}
			plan.Retired = append(plan.Retired, vipChange{IP: ip, Host: host})
		}
	}

	for _, host := range slices.Sorted(maps.Keys(hosts)) {
		if _, ok := plan.Hosts[host]; ok || host == "" {
			continue
		}
		if len(plan.Entries) >= capacity && !plan.evictOldestRetired() {
			plan.Unallocated = append(plan.Unallocated, host)
			continue
		}
		ip, ok := freeVirtualIP(r, host, plan.Entries)
		if !ok {
			plan.Unallocated = append(plan.Unallocated, host)
			continue
		}
		plan.Entries[ip] = vipEntry{Host: host}
		plan.Hosts[host] = ip
		plan.Allocated = append(plan.Allocated, vipChange{IP: ip, Host: host})
	}
	return plan
}

// evictOldestRetired releases the retired reservation retired the longest
// ago (lowest IP on a tie). Reports whether there was one.
func (p *vipPlan) evictOldestRetired() bool {
	var oldest netip.Addr
	for ip, e := range p.Entries {
		if !e.Retired {
			continue
		}
		if !oldest.IsValid() {
			oldest = ip
			continue
		}
		o := p.Entries[oldest]
		if c := cmp.Compare(e.RetiredAt.Unix(), o.RetiredAt.Unix()); c < 0 || (c == 0 && ip.Less(oldest)) {
			oldest = ip
		}
	}
	if !oldest.IsValid() {
		return false
	}
	p.Released = append(p.Released, vipChange{IP: oldest, Host: p.Entries[oldest].Host, Reason: "evicted to make room"})
	delete(p.Entries, oldest)
	return true
}

// freeVirtualIP returns the first address of r at or after host's hash slot
// that is usable and not taken.
func freeVirtualIP(r netip.Prefix, host string, taken map[netip.Addr]vipEntry) (netip.Addr, bool) {
	size := uint64(1) << (32 - r.Bits())
	base := binary.BigEndian.Uint32(r.Addr().AsSlice())
	h := fnv.New64a()
	_, _ = h.Write([]byte(host))
	start := h.Sum64() % size
	for i := range size {
		off := (start + i) % size
		if off == 0 || off == size-1 {
			continue // network and broadcast address of the range
		}
		v := base + uint32(off)
		if last := byte(v); last == 0 || last == 0xff {
			continue // some software rejects .0 / .255 addresses
		}
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], v)
		ip := netip.AddrFrom4(a)
		if _, ok := taken[ip]; !ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}
