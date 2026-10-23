package ebpf

import (
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DefaultVirtualIPRange is the default --virtual-ip-range: the IPv4 and IPv6
// ranges reserved for benchmarking (RFC 2544, RFC 5180), which should never
// be routed. The IPv6 one is global unicast as far as address selection
// (RFC 6724) goes, like the public addresses of most hosts it stands in for,
// so apps prefer IPv6 or IPv4 for a fake IP as they would for the real one.
const DefaultVirtualIPRange = "198.18.0.0/15,2001:2::/48"

// DefaultBPFPinPath is the bpffs directory kloak pins its maps in.
const DefaultBPFPinPath = "/sys/fs/bpf/kloak"

// minVirtualIPHostBits sets the smallest range accepted, a /19 in IPv4 and a
// /115 in IPv6: 2^13 addresses are twice vip_ip_host's 4096 entries, so
// probing for a free address stays short and the map, not the range, is
// what fills up first.
const minVirtualIPHostBits = 13

// virtualIPRetention is how long a fake IP stays reserved for a host that is
// no longer watched. Apps cache DNS answers, so handing the IP to another
// host right away could send that app's traffic to the wrong host.
const virtualIPRetention = 24 * time.Hour

// v4MappedPrefix holds the IPv4-mapped IPv6 addresses, which the data plane
// reads as IPv4.
var v4MappedPrefix = netip.MustParsePrefix("::ffff:0.0.0.0/96")

// VirtualIPRanges are the ranges fake IPs come from.
type VirtualIPRanges struct {
	// V4 is the IPv4 range; required.
	V4 netip.Prefix
	// V6 is the IPv6 range. Without one (the zero Prefix), hosts get no fake
	// IPv6 and AAAA answers are left unchanged.
	V6 netip.Prefix
}

// Prefixes returns the ranges that are set, IPv4 first.
func (r VirtualIPRanges) Prefixes() []netip.Prefix {
	out := []netip.Prefix{r.V4}
	if r.V6.IsValid() {
		out = append(out, r.V6)
	}
	return out
}

// String formats r as a --virtual-ip-range value.
func (r VirtualIPRanges) String() string {
	var parts []string
	for _, p := range r.Prefixes() {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

// ParseVirtualIPRanges validates a --virtual-ip-range value: an IPv4 range
// and optionally an IPv6 one, comma-separated (like Kubernetes' dual-stack
// CIDR flags), each a network address of at least 2^13 addresses.
func ParseVirtualIPRanges(s string) (VirtualIPRanges, error) {
	var r VirtualIPRanges
	for _, part := range strings.Split(s, ",") {
		p, err := parseVirtualIPPrefix(part)
		if err != nil {
			return VirtualIPRanges{}, err
		}
		slot, family := &r.V4, "IPv4"
		if p.Addr().Is6() {
			slot, family = &r.V6, "IPv6"
		}
		if slot.IsValid() {
			return VirtualIPRanges{}, fmt.Errorf("virtual IP range %q has more than one %s range", s, family)
		}
		*slot = p
	}
	if !r.V4.IsValid() {
		return VirtualIPRanges{}, fmt.Errorf("virtual IP range %q has no IPv4 range", s)
	}
	return r, nil
}

// parseVirtualIPPrefix validates one range of a --virtual-ip-range value.
func parseVirtualIPPrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid virtual IP range %q: %w", s, err)
	}
	if p.Addr().Is6() && p.Overlaps(v4MappedPrefix) {
		return netip.Prefix{}, fmt.Errorf("virtual IP range %q overlaps the IPv4-mapped addresses %s", s, v4MappedPrefix)
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("virtual IP range %q has host bits set (did you mean %s?)", s, p.Masked())
	}
	if maxBits := p.Addr().BitLen() - minVirtualIPHostBits; p.Bits() > maxBits {
		return netip.Prefix{}, fmt.Errorf("virtual IP range %q is too small (want /%d or larger)", s, maxBits)
	}
	return p, nil
}

// HostResolutionConfig is the host resolution setup of a TLSUprobeManager:
// every watched host gets a stable fake IP (and fake IPv6) from
// VirtualIPRanges, kept in maps pinned in bpffs, the pods with a secret for
// the host get it in DNS answers, and a host-restricted secret is decided on
// the socket that connected to it (spinningfactory/kloak#327). It is passed
// at construction rather than through a setter because the virtual IP maps
// are pinned when the BPF objects are loaded.
type HostResolutionConfig struct {
	// VirtualIPRanges are the ranges fake IPs come from (see
	// ParseVirtualIPRanges).
	VirtualIPRanges VirtualIPRanges
	// PinPath is the bpffs directory the virtual IP maps are pinned in.
	// Empty means DefaultBPFPinPath.
	PinPath string
}

func (c *HostResolutionConfig) pinPath() string {
	if c.PinPath == "" {
		return DefaultBPFPinPath
	}
	return c.PinPath
}

func (c *HostResolutionConfig) validate() error {
	r := c.VirtualIPRanges
	if !r.V4.IsValid() {
		return fmt.Errorf("host resolution needs an IPv4 virtual IP range")
	}
	if !r.V4.Addr().Is4() || (r.V6.IsValid() && !r.V6.Addr().Is6()) {
		return fmt.Errorf("virtual IP ranges %s are of the wrong family", r)
	}
	_, err := ParseVirtualIPRanges(r.String())
	return err
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

// HostRoutes returns the IPv4 and IPv6 routes of the network namespace of
// the process whose procfs directory is procDir (for example "/proc/1" for
// the host, with hostPID), default routes included. A kernel without IPv6
// (no ipv6_route) has no IPv6 routes.
func HostRoutes(procDir string) ([]ReservedRange, error) {
	path := filepath.Join(procDir, "net", "route")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	routes := parseRoutes(data)
	path = filepath.Join(procDir, "net", "ipv6_route")
	data, err = os.ReadFile(path)
	switch {
	case err == nil:
		routes = append(routes, parseRoutes6(data)...)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var out []ReservedRange
	for _, rt := range routes {
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

// parseRoutes6 reads the destination of every row of a /proc/net/ipv6_route
// body: "dst dst_len src src_len next_hop metric refcnt use flags iface",
// the addresses as 32 hex digits in network byte order, the lengths as 2.
// Rows that don't parse are skipped.
func parseRoutes6(data []byte) []route {
	var out []route
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		b, err := hex.DecodeString(fields[0])
		if err != nil || len(b) != 16 {
			continue
		}
		plen, err := strconv.ParseUint(fields[1], 16, 8)
		if err != nil || plen > 128 {
			continue
		}
		dst := netip.PrefixFrom(netip.AddrFrom16([16]byte(b)), int(plen)).Masked()
		out = append(out, route{iface: fields[9], dst: dst})
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

// planVirtualIPRanges plans the reservations of each of ranges with
// planVirtualIPs: the IPv4 range's from the existing IPv4 reservations, the
// IPv6 range's from the IPv6 ones. Without an IPv6 range every IPv6
// reservation is released. The two share vip_ip_host's capacity: with an
// IPv6 range each family gets half.
func planVirtualIPRanges(ranges VirtualIPRanges, hosts map[string]struct{}, existing map[netip.Addr]vipEntry, now time.Time, capacity int) (v4, v6 vipPlan) {
	ex4 := make(map[netip.Addr]vipEntry)
	ex6 := make(map[netip.Addr]vipEntry)
	for ip, e := range existing {
		if ip.Is4() {
			ex4[ip] = e
		} else {
			ex6[ip] = e
		}
	}
	cap4, hosts6 := capacity, map[string]struct{}(nil)
	if ranges.V6.IsValid() {
		cap4, hosts6 = capacity/2, hosts
	}
	return planVirtualIPs(ranges.V4, hosts, ex4, now, cap4),
		planVirtualIPs(ranges.V6, hosts6, ex6, now, capacity-cap4)
}

// planVirtualIPs works out the reservations of range r for the watched
// hosts, given the existing ones of r's family (read back from the pinned
// vip_ip_host) and room for capacity entries:
//
//   - an existing reservation is kept: a host keeps its fake IP for as long
//     as it is watched, and a retired host that is watched again gets its
//     old IP back;
//   - a new host gets the first free address at or after
//     fnv1a64(host) mod size(r) (freeVirtualIP). Hosts are allocated in
//     sorted order, so the result does not depend on map iteration order;
//   - a reservation whose host is no longer watched is retired, and
//     released once virtualIPRetention has passed;
//   - reservations outside r (the range was changed, or r is the zero
//     Prefix: no range of their family) are released;
//   - retired reservations beyond capacity (its share of the map shrank)
//     are evicted, oldest first;
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
		case !r.IsValid():
			reason = "no virtual IP range of its family"
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

	for len(plan.Entries) > capacity && plan.evictOldestRetired() {
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
	h := fnv.New64a()
	_, _ = h.Write([]byte(host))
	if r.Addr().Is6() {
		return freeVirtualIP6(r, h.Sum64(), taken)
	}
	return freeVirtualIP4(r, h.Sum64(), taken)
}

// freeVirtualIP4 probes the IPv4 range r from offset hash mod its size,
// skipping the first and last address of r and every address ending in .0
// or .255.
func freeVirtualIP4(r netip.Prefix, hash uint64, taken map[netip.Addr]vipEntry) (netip.Addr, bool) {
	size := uint64(1) << (32 - r.Bits())
	base := binary.BigEndian.Uint32(r.Addr().AsSlice())
	start := hash % size
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

// freeVirtualIP6 probes the IPv6 range r from offset hash mod its size,
// skipping the first and last address of r. Offsets span at most the low
// 64 bits (the interface identifier of a /64 or larger range), so in a range
// larger than a /64 every fake IP is in its first /64.
func freeVirtualIP6(r netip.Prefix, hash uint64, taken map[netip.Addr]vipEntry) (netip.Addr, bool) {
	last := ^uint64(0) // the largest offset, 2^64 - 1 unless r is smaller
	if hostBits := 128 - r.Bits(); hostBits < 64 {
		last = uint64(1)<<hostBits - 1
	}
	base := r.Addr().As16()
	lo := binary.BigEndian.Uint64(base[8:]) // zero where offsets go
	start := hash
	if last != ^uint64(0) {
		start %= last + 1
	}
	// At most len(taken) addresses are taken: that many steps past the
	// two skipped addresses find a free one, if r has one.
	for i := range uint64(len(taken)) + 3 {
		off := start + i
		if last != ^uint64(0) {
			off %= last + 1
		}
		if off == 0 || off == last {
			continue
		}
		a := base
		binary.BigEndian.PutUint64(a[8:], lo|off)
		ip := netip.AddrFrom16(a)
		if _, ok := taken[ip]; !ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}
