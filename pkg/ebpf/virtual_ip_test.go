package ebpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseHostResolutionMode(t *testing.T) {
	for in, want := range map[string]HostResolutionMode{
		"":            HostResolutionDNSSnoop,
		"dns-snoop":   HostResolutionDNSSnoop,
		" Virtual-IP": HostResolutionVirtualIP,
	} {
		got, err := ParseHostResolutionMode(in)
		if err != nil || got != want {
			t.Errorf("ParseHostResolutionMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseHostResolutionMode("stub"); err == nil {
		t.Error("ParseHostResolutionMode(stub) succeeded")
	}
}

func TestParseVirtualIPRanges(t *testing.T) {
	want := VirtualIPRanges{V4: netip.MustParsePrefix("198.18.0.0/15"), V6: netip.MustParsePrefix("2001:2::/48")}
	if got, err := ParseVirtualIPRanges(DefaultVirtualIPRange); err != nil || got != want {
		t.Fatalf("default ranges: %v, %v", got, err)
	}
	if want.String() != DefaultVirtualIPRange {
		t.Errorf("String() = %q", want.String())
	}
	for in, want := range map[string]VirtualIPRanges{
		"10.200.0.0/19":                {V4: netip.MustParsePrefix("10.200.0.0/19")},
		"fd00:6b6c::/115, 10.0.0.0/16": {V4: netip.MustParsePrefix("10.0.0.0/16"), V6: netip.MustParsePrefix("fd00:6b6c::/115")},
	} {
		if got, err := ParseVirtualIPRanges(in); err != nil || got != want {
			t.Errorf("ParseVirtualIPRanges(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"",
		"198.18.0.0",                      // not a prefix
		"198.18.1.0/15",                   // host bits set
		"10.200.0.0/20",                   // too small
		"fd00:6b6c::/64",                  // no IPv4 range
		"198.18.0.0/15,fd00::/116",        // IPv6 range too small
		"198.18.0.0/15,fd00::1/64",        // IPv6 host bits set
		"198.18.0.0/15,::ffff:0.0.0.0/96", // IPv4-mapped IPv6
		"198.18.0.0/15,::/0",              // holds the IPv4-mapped addresses
		"::ffff:198.18.0.0/111",           // IPv4-mapped IPv6 only
		"198.18.0.0/15,10.0.0.0/16",       // two IPv4 ranges
		"198.18.0.0/15,fd00::/64,fd01::/64",
		"198.18.0.0/15,",
	} {
		if _, err := ParseVirtualIPRanges(bad); err == nil {
			t.Errorf("ParseVirtualIPRanges(%q) succeeded", bad)
		}
	}
}

func TestHostResolutionConfigValidate(t *testing.T) {
	ok := []HostResolutionConfig{
		{},
		{Mode: HostResolutionDNSSnoop},
		{Mode: HostResolutionVirtualIP, VirtualIPRanges: testVIPRanges},
		{Mode: HostResolutionVirtualIP, VirtualIPRanges: VirtualIPRanges{V4: testVIPRange}},
	}
	for _, c := range ok {
		if err := c.validate(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	bad := []HostResolutionConfig{
		{Mode: "stub"},
		{Mode: HostResolutionVirtualIP},
		{Mode: HostResolutionVirtualIP, VirtualIPRanges: VirtualIPRanges{V4: netip.MustParsePrefix("10.0.0.0/24")}},
		{Mode: HostResolutionVirtualIP, VirtualIPRanges: VirtualIPRanges{V6: testVIPRange6}},
		{Mode: HostResolutionVirtualIP, VirtualIPRanges: VirtualIPRanges{V4: testVIPRange6}},
		{Mode: HostResolutionVirtualIP, VirtualIPRanges: VirtualIPRanges{V4: testVIPRange, V6: testVIPRange}},
	}
	for _, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("%+v: validated", c)
		}
	}
	if got := (&HostResolutionConfig{}).pinPath(); got != DefaultBPFPinPath {
		t.Errorf("default pin path %q", got)
	}
}

func TestCheckVirtualIPRange(t *testing.T) {
	r := testVIPRange
	clear := []ReservedRange{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Source: "default route"},
		{Prefix: netip.MustParsePrefix("10.42.0.0/16"), Source: "pod CIDR"},
		{Prefix: netip.MustParsePrefix("198.20.0.0/16"), Source: "just above"},
		{Prefix: netip.MustParsePrefix("fd00::/8"), Source: "IPv6"},
	}
	if err := CheckVirtualIPRange(r, clear); err != nil {
		t.Fatalf("no overlap expected: %v", err)
	}

	conflicting := append(clear,
		ReservedRange{Prefix: netip.MustParsePrefix("198.19.4.7/32"), Source: "address of node a"},
		ReservedRange{Prefix: netip.MustParsePrefix("198.0.0.0/8"), Source: "node route via eth1"},
	)
	err := CheckVirtualIPRange(r, conflicting)
	if err == nil {
		t.Fatal("overlap not detected")
	}
	for _, want := range []string{"198.19.4.7/32 (address of node a)", "198.0.0.0/8 (node route via eth1)", "--virtual-ip-range"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "pod CIDR") || strings.Contains(err.Error(), "default route") {
		t.Errorf("error %q names a range that does not overlap", err)
	}

	// The IPv6 range against IPv6 ranges.
	clear6 := []ReservedRange{
		{Prefix: netip.MustParsePrefix("::/0"), Source: "default route"},
		{Prefix: netip.MustParsePrefix("fd42::/56"), Source: "pod CIDR"},
		{Prefix: netip.MustParsePrefix("2001:3::/32"), Source: "just above"},
		{Prefix: netip.MustParsePrefix("198.18.0.0/15"), Source: "IPv4"},
	}
	if err := CheckVirtualIPRange(testVIPRange6, clear6); err != nil {
		t.Fatalf("no IPv6 overlap expected: %v", err)
	}
	err = CheckVirtualIPRange(testVIPRange6, append(clear6, ReservedRange{Prefix: netip.MustParsePrefix("2000::/3"), Source: "node route via eth0"}))
	if err == nil || !strings.Contains(err.Error(), "2000::/3 (node route via eth0)") {
		t.Errorf("IPv6 overlap: %v", err)
	}
}

// routeHex formats an address the way /proc/net/route prints it: the hex of
// its in-memory __be32 read as a native-endian integer.
func routeHex(s string) string {
	return fmt.Sprintf("%08X", binary.NativeEndian.Uint32(netip.MustParseAddr(s).AsSlice()))
}

func routeTable(rows ...[3]string) string {
	var b strings.Builder
	b.WriteString("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s\t%s\t00000000\t0001\t0\t0\t0\t%s\t0\t0\t0\n", r[0], routeHex(r[1]), routeHex(r[2]))
	}
	return b.String()
}

func TestParseRoutes(t *testing.T) {
	data := routeTable(
		[3]string{"eth0", "0.0.0.0", "0.0.0.0"},
		[3]string{"cni0", "10.42.0.0", "255.255.255.0"},
		[3]string{"tun0", "198.18.0.0", "255.254.0.0"},
		[3]string{"eth0", "192.168.5.15", "255.255.255.255"},
		[3]string{"bad", "10.0.0.0", "255.0.255.0"}, // non-contiguous mask
	) + "short line\n\n"

	got := parseRoutes([]byte(data))
	want := []route{
		{iface: "eth0", dst: netip.MustParsePrefix("0.0.0.0/0")},
		{iface: "cni0", dst: netip.MustParsePrefix("10.42.0.0/24")},
		{iface: "tun0", dst: netip.MustParsePrefix("198.18.0.0/15")},
		{iface: "eth0", dst: netip.MustParsePrefix("192.168.5.15/32")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseRoutes:\n got %v\nwant %v", got, want)
	}
}

// route6Line formats a /proc/net/ipv6_route row for dst.
func route6Line(dst, iface string) string {
	p := netip.MustParsePrefix(dst)
	a := p.Addr().As16()
	return fmt.Sprintf("%x %02x 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 %8s\n",
		a[:], p.Bits(), iface)
}

func TestParseRoutes6(t *testing.T) {
	data := route6Line("fd42::/64", "cni0") + route6Line("::1/128", "lo") + route6Line("::/0", "eth0") +
		route6Line("fe80::/64", "eth0") +
		"fd42 40 short\n" + // too few fields
		"zz00000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n" +
		"fd420000000000000000000000000000 81 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n" // length > 128
	got := parseRoutes6([]byte(data))
	want := []route{
		{iface: "cni0", dst: netip.MustParsePrefix("fd42::/64")},
		{iface: "lo", dst: netip.MustParsePrefix("::1/128")},
		{iface: "eth0", dst: netip.MustParsePrefix("::/0")},
		{iface: "eth0", dst: netip.MustParsePrefix("fe80::/64")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseRoutes6:\n got %v\nwant %v", got, want)
	}
}

func TestHostRoutes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := routeTable([3]string{"cni0", "10.42.0.0", "255.255.255.0"})
	if err := os.WriteFile(filepath.Join(dir, "net", "route"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	// No ipv6_route: a kernel without IPv6.
	got, err := HostRoutes(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []ReservedRange{{Prefix: netip.MustParsePrefix("10.42.0.0/24"), Source: "node route via cni0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HostRoutes = %v, want %v", got, want)
	}

	if err := os.WriteFile(filepath.Join(dir, "net", "ipv6_route"), []byte(route6Line("fd42::/64", "cni0")), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = HostRoutes(dir)
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, ReservedRange{Prefix: netip.MustParsePrefix("fd42::/64"), Source: "node route via cni0"})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HostRoutes = %v, want %v", got, want)
	}
	if _, err := HostRoutes(filepath.Join(dir, "missing")); err == nil {
		t.Error("HostRoutes on a missing directory succeeded")
	}
}

var (
	testVIPRanges = mustVirtualIPRanges(DefaultVirtualIPRange)
	testVIPRange  = testVIPRanges.V4
	testVIPRange6 = testVIPRanges.V6
	testVIPNow    = time.Unix(1_800_000_000, 0)
)

func mustVirtualIPRanges(s string) VirtualIPRanges {
	r, err := ParseVirtualIPRanges(s)
	if err != nil {
		panic(err)
	}
	return r
}

func hostSet(hosts ...string) map[string]struct{} {
	s := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		s[h] = struct{}{}
	}
	return s
}

// usableVirtualIP reports whether freeVirtualIP may hand out ip from r.
func usableVirtualIP(r netip.Prefix, ip netip.Addr) bool {
	if !r.Contains(ip) {
		return false
	}
	if ip.Is6() {
		// Not the first or last address of r's first /64.
		first := netip.PrefixFrom(r.Addr(), max(r.Bits(), 64)).Masked()
		lastOff := ^uint64(0) >> max(r.Bits()-64, 0)
		a := ip.As16()
		off := binary.BigEndian.Uint64(a[8:]) & lastOff
		return first.Contains(ip) && off != 0 && off != lastOff
	}
	v := binary.BigEndian.Uint32(ip.AsSlice())
	base := binary.BigEndian.Uint32(r.Addr().AsSlice())
	last := base + uint32(uint64(1)<<(32-r.Bits())-1)
	return v != base && v != last && byte(v) != 0 && byte(v) != 0xff
}

func TestPlanVirtualIPsAllocates(t *testing.T) {
	hosts := hostSet("api.example.com", "b.example.com", "c.example.com")
	plan := planVirtualIPs(testVIPRange, hosts, nil, testVIPNow, 4096)

	if len(plan.Hosts) != 3 || len(plan.Entries) != 3 || len(plan.Allocated) != 3 {
		t.Fatalf("plan = %+v", plan)
	}
	seen := map[netip.Addr]bool{}
	for host, ip := range plan.Hosts {
		if !usableVirtualIP(testVIPRange, ip) {
			t.Errorf("%s got unusable %s", host, ip)
		}
		if seen[ip] {
			t.Errorf("%s shares %s", host, ip)
		}
		seen[ip] = true
		if e := plan.Entries[ip]; e != (vipEntry{Host: host}) {
			t.Errorf("entry for %s = %+v", ip, e)
		}
	}

	// Deterministic: the same hosts get the same IPs from scratch, here
	// and on another node.
	for range 5 {
		again := planVirtualIPs(testVIPRange, hosts, nil, testVIPNow, 4096)
		if !reflect.DeepEqual(again.Hosts, plan.Hosts) {
			t.Fatalf("allocation not deterministic: %v vs %v", again.Hosts, plan.Hosts)
		}
	}
}

func TestPlanVirtualIPsKeepsExisting(t *testing.T) {
	// A pinned reservation wins over the hash slot.
	pinned := netip.MustParseAddr("198.18.7.7")
	existing := map[netip.Addr]vipEntry{pinned: {Host: "api.example.com"}}
	plan := planVirtualIPs(testVIPRange, hostSet("api.example.com"), existing, testVIPNow, 4096)

	if plan.Hosts["api.example.com"] != pinned {
		t.Fatalf("host moved to %s", plan.Hosts["api.example.com"])
	}
	if len(plan.Allocated)+len(plan.Retired)+len(plan.Released)+len(plan.Reactivated) != 0 {
		t.Errorf("unexpected changes: %+v", plan)
	}
}

func TestPlanVirtualIPsProbesPastTakenSlot(t *testing.T) {
	// A small range makes the probe walk visible: offsets 1..6 are usable.
	r := netip.MustParsePrefix("10.0.0.0/29")
	home, ok := freeVirtualIP(r, "new.example.com", nil)
	if !ok {
		t.Fatal("no free IP in an empty range")
	}
	existing := map[netip.Addr]vipEntry{home: {Host: "old.example.com"}}
	plan := planVirtualIPs(r, hostSet("old.example.com", "new.example.com"), existing, testVIPNow, 4096)

	got := plan.Hosts["new.example.com"]
	if got == home || !usableVirtualIP(r, got) {
		t.Fatalf("new host got %s (home slot %s taken)", got, home)
	}
	if plan.Hosts["old.example.com"] != home {
		t.Errorf("old host moved to %s", plan.Hosts["old.example.com"])
	}
	// The first free address after home, wrapping and skipping the range's
	// network (.0) and broadcast (.7) addresses.
	want := home.Next()
	if want == netip.MustParseAddr("10.0.0.7") {
		want = netip.MustParseAddr("10.0.0.1")
	}
	if got != want {
		t.Errorf("new host got %s, want %s", got, want)
	}
}

func TestPlanVirtualIPsCollisionOrderIndependent(t *testing.T) {
	// With every address but two taken, whichever new host is allocated
	// first wins the lower address. Sorted processing makes that the same
	// host on every run, whatever the map order.
	r := netip.MustParsePrefix("10.0.0.0/29")
	existing := map[netip.Addr]vipEntry{}
	for i := 1; i <= 4; i++ {
		existing[netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})] = vipEntry{Host: fmt.Sprintf("taken-%d", i)}
	}
	hosts := hostSet("taken-1", "taken-2", "taken-3", "taken-4", "z.example.com", "a.example.com")
	first := planVirtualIPs(r, hosts, existing, testVIPNow, 4096)
	for range 20 {
		if again := planVirtualIPs(r, hosts, existing, testVIPNow, 4096); !reflect.DeepEqual(again.Hosts, first.Hosts) {
			t.Fatalf("allocation depends on order: %v vs %v", again.Hosts, first.Hosts)
		}
	}
	if len(first.Unallocated) != 0 {
		t.Fatalf("unallocated: %v", first.Unallocated)
	}
}

func TestPlanVirtualIPsRetireAndReactivate(t *testing.T) {
	ip := netip.MustParseAddr("198.18.7.7")
	existing := map[netip.Addr]vipEntry{ip: {Host: "api.example.com"}}

	// The host is no longer watched: its IP is retired, not freed.
	plan := planVirtualIPs(testVIPRange, hostSet(), existing, testVIPNow, 4096)
	if _, ok := plan.Hosts["api.example.com"]; ok {
		t.Fatal("retired host still in vip_host_ip")
	}
	want := vipEntry{Host: "api.example.com", Retired: true, RetiredAt: testVIPNow}
	if plan.Entries[ip] != want || len(plan.Retired) != 1 {
		t.Fatalf("entries %+v retired %+v", plan.Entries, plan.Retired)
	}

	// Another host never takes a retired IP, even when it hashes there.
	r := netip.MustParsePrefix("10.0.0.0/29")
	home, _ := freeVirtualIP(r, "other.example.com", nil)
	retired := map[netip.Addr]vipEntry{home: want}
	if got := planVirtualIPs(r, hostSet("other.example.com"), retired, testVIPNow, 4096).Hosts["other.example.com"]; got == home {
		t.Fatalf("retired IP %s reused", home)
	}

	// Watched again within the retention period: same IP, active again.
	later := testVIPNow.Add(time.Hour)
	plan = planVirtualIPs(testVIPRange, hostSet("api.example.com"), plan.Entries, later, 4096)
	if plan.Hosts["api.example.com"] != ip || plan.Entries[ip] != (vipEntry{Host: "api.example.com"}) || len(plan.Reactivated) != 1 {
		t.Fatalf("not reactivated: %+v", plan)
	}
}

func TestPlanVirtualIPsReleases(t *testing.T) {
	retiredIP := netip.MustParseAddr("198.18.7.7")
	freshIP := netip.MustParseAddr("198.18.7.8")
	outsideIP := netip.MustParseAddr("10.0.0.5")
	existing := map[netip.Addr]vipEntry{
		retiredIP:                         {Host: "old.example.com", Retired: true, RetiredAt: testVIPNow.Add(-virtualIPRetention)},
		freshIP:                           {Host: "recent.example.com", Retired: true, RetiredAt: testVIPNow.Add(-time.Minute)},
		outsideIP:                         {Host: "moved.example.com"}, // the range was changed
		netip.MustParseAddr("198.18.7.9"): {},                          // no host
	}
	plan := planVirtualIPs(testVIPRange, hostSet("moved.example.com"), existing, testVIPNow, 4096)

	if _, ok := plan.Entries[retiredIP]; ok {
		t.Error("expired reservation kept")
	}
	if _, ok := plan.Entries[freshIP]; !ok {
		t.Error("reservation released before the retention period is over")
	}
	if _, ok := plan.Entries[outsideIP]; ok {
		t.Error("reservation outside the range kept")
	}
	if ip := plan.Hosts["moved.example.com"]; !testVIPRange.Contains(ip) {
		t.Errorf("moved host got %s", ip)
	}
	if len(plan.Released) != 3 {
		t.Errorf("released %+v", plan.Released)
	}
}

func TestPlanVirtualIPsCapacity(t *testing.T) {
	a := netip.MustParseAddr("198.18.1.1")
	b := netip.MustParseAddr("198.18.1.2")
	full := map[netip.Addr]vipEntry{a: {Host: "a.example.com"}, b: {Host: "b.example.com"}}

	plan := planVirtualIPs(testVIPRange, hostSet("a.example.com", "b.example.com", "c.example.com"), full, testVIPNow, 2)
	if !reflect.DeepEqual(plan.Unallocated, []string{"c.example.com"}) || len(plan.Entries) != 2 {
		t.Fatalf("full map: unallocated %v, entries %v", plan.Unallocated, plan.Entries)
	}

	// The oldest retired reservation makes room.
	withRetired := map[netip.Addr]vipEntry{
		a: {Host: "a.example.com", Retired: true, RetiredAt: testVIPNow.Add(-2 * time.Hour)},
		b: {Host: "b.example.com", Retired: true, RetiredAt: testVIPNow.Add(-time.Hour)},
	}
	plan = planVirtualIPs(testVIPRange, hostSet("c.example.com"), withRetired, testVIPNow, 2)
	if _, ok := plan.Entries[a]; ok {
		t.Error("oldest retired reservation not evicted")
	}
	if _, ok := plan.Entries[b]; !ok {
		t.Error("newer retired reservation evicted")
	}
	if _, ok := plan.Hosts["c.example.com"]; !ok || len(plan.Unallocated) != 0 {
		t.Errorf("c not allocated: %+v", plan)
	}
}

func TestPlanVirtualIPsOneActiveIPPerHost(t *testing.T) {
	low := netip.MustParseAddr("198.18.1.1")
	high := netip.MustParseAddr("198.18.1.2")

	// Two active IPs: the lower one is kept, the other retired.
	plan := planVirtualIPs(testVIPRange, hostSet("api.example.com"),
		map[netip.Addr]vipEntry{low: {Host: "api.example.com"}, high: {Host: "api.example.com"}}, testVIPNow, 4096)
	if plan.Hosts["api.example.com"] != low || !plan.Entries[high].Retired {
		t.Fatalf("two active: %+v", plan)
	}

	// An active IP wins over a retired one.
	plan = planVirtualIPs(testVIPRange, hostSet("api.example.com"), map[netip.Addr]vipEntry{
		low:  {Host: "api.example.com", Retired: true, RetiredAt: testVIPNow},
		high: {Host: "api.example.com"},
	}, testVIPNow, 4096)
	if plan.Hosts["api.example.com"] != high || len(plan.Reactivated) != 0 || !plan.Entries[low].Retired {
		t.Fatalf("active vs retired: %+v", plan)
	}
}

func TestPlanVirtualIPsIPv6(t *testing.T) {
	hosts := hostSet("api.example.com", "b.example.com", "c.example.com")
	plan := planVirtualIPs(testVIPRange6, hosts, nil, testVIPNow, 2048)
	if len(plan.Hosts) != 3 || len(plan.Entries) != 3 || len(plan.Allocated) != 3 {
		t.Fatalf("plan = %+v", plan)
	}
	seen := map[netip.Addr]bool{}
	for host, ip := range plan.Hosts {
		if !ip.Is6() || !usableVirtualIP(testVIPRange6, ip) {
			t.Errorf("%s got unusable %s", host, ip)
		}
		if seen[ip] {
			t.Errorf("%s shares %s", host, ip)
		}
		seen[ip] = true
	}
	if again := planVirtualIPs(testVIPRange6, hosts, nil, testVIPNow, 2048); !reflect.DeepEqual(again.Hosts, plan.Hosts) {
		t.Fatalf("allocation not deterministic: %v vs %v", again.Hosts, plan.Hosts)
	}
	// A kept reservation wins, as in IPv4.
	pinned := netip.MustParseAddr("2001:2::7")
	plan = planVirtualIPs(testVIPRange6, hostSet("api.example.com"), map[netip.Addr]vipEntry{pinned: {Host: "api.example.com"}}, testVIPNow, 2048)
	if plan.Hosts["api.example.com"] != pinned || len(plan.Allocated) != 0 {
		t.Fatalf("kept reservation: %+v", plan)
	}
}

func TestFreeVirtualIP6(t *testing.T) {
	// A /126 holds offsets 0..3; 0 and 3 are skipped.
	r := netip.MustParsePrefix("fd00::/126")
	taken := map[netip.Addr]vipEntry{}
	for range 2 {
		ip, ok := freeVirtualIP(r, "api.example.com", taken)
		if !ok || (ip != netip.MustParseAddr("fd00::1") && ip != netip.MustParseAddr("fd00::2")) {
			t.Fatalf("got %s, %v (taken %v)", ip, ok, taken)
		}
		taken[ip] = vipEntry{Host: "x"}
	}
	if ip, ok := freeVirtualIP(r, "api.example.com", taken); ok {
		t.Fatalf("full range handed out %s", ip)
	}

	// Past a /64, offsets fill the low 64 bits of the first /64; probing
	// wraps past the all-ones offset.
	big := netip.MustParsePrefix("2001:2::/48")
	ip, ok := freeVirtualIP6(big, ^uint64(0), nil)
	if !ok || ip != netip.MustParseAddr("2001:2::1") {
		t.Fatalf("all-ones start: %s, %v", ip, ok)
	}
	ip, ok = freeVirtualIP6(big, 0x1234, map[netip.Addr]vipEntry{netip.MustParseAddr("2001:2::1234"): {}})
	if !ok || ip != netip.MustParseAddr("2001:2::1235") {
		t.Fatalf("probe past a taken address: %s, %v", ip, ok)
	}
	// A /96: offsets stay below 2^32, network bits intact.
	small := netip.MustParsePrefix("fd00:1:2:3:4:5::/96")
	ip, ok = freeVirtualIP6(small, 0x1_0000_0005, nil)
	if !ok || ip != netip.MustParseAddr("fd00:1:2:3:4:5:0:5") {
		t.Fatalf("/96: %s, %v", ip, ok)
	}
}

func TestPlanVirtualIPRanges(t *testing.T) {
	v4 := netip.MustParseAddr("198.18.7.7")
	v6 := netip.MustParseAddr("2001:2::7")
	existing := map[netip.Addr]vipEntry{v4: {Host: "api.example.com"}, v6: {Host: "api.example.com"}}

	// Each family plans its own reservations; a host gets one IP of each.
	p4, p6 := planVirtualIPRanges(testVIPRanges, hostSet("api.example.com", "b.example.com"), existing, testVIPNow, 8)
	if p4.Hosts["api.example.com"] != v4 || p6.Hosts["api.example.com"] != v6 {
		t.Fatalf("kept: %v %v", p4.Hosts, p6.Hosts)
	}
	if !p4.Hosts["b.example.com"].Is4() || !p6.Hosts["b.example.com"].Is6() {
		t.Fatalf("new host: %v %v", p4.Hosts, p6.Hosts)
	}
	if len(p4.Released)+len(p6.Released) != 0 {
		t.Errorf("released %v %v", p4.Released, p6.Released)
	}

	// Capacity is split: 2 of 4 entries each.
	p4, p6 = planVirtualIPRanges(testVIPRanges, hostSet("a", "b", "c"), nil, testVIPNow, 4)
	if len(p4.Entries) != 2 || len(p6.Entries) != 2 || len(p4.Unallocated) != 1 || len(p6.Unallocated) != 1 {
		t.Fatalf("split capacity: v4 %v / %v, v6 %v / %v", p4.Entries, p4.Unallocated, p6.Entries, p6.Unallocated)
	}

	// Without an IPv6 range: IPv4 gets the whole map, every IPv6
	// reservation is released and no host gets one.
	p4, p6 = planVirtualIPRanges(VirtualIPRanges{V4: testVIPRange}, hostSet("api.example.com"), existing, testVIPNow, 4)
	if p4.Hosts["api.example.com"] != v4 || len(p6.Hosts) != 0 || len(p6.Entries) != 0 {
		t.Fatalf("no IPv6 range: %v %v", p4.Hosts, p6)
	}
	if len(p6.Released) != 1 || p6.Released[0].IP != v6 || p6.Released[0].Reason != "no virtual IP range of its family" {
		t.Errorf("released %+v", p6.Released)
	}
	p4, _ = planVirtualIPRanges(VirtualIPRanges{V4: testVIPRange}, hostSet("a", "b", "c", "d"), nil, testVIPNow, 4)
	if len(p4.Entries) != 4 {
		t.Errorf("IPv4 alone got %d entries of 4", len(p4.Entries))
	}
}

func TestPlanVirtualIPsTrimsToCapacity(t *testing.T) {
	// The share of the map shrank (an IPv6 range was added): retired
	// reservations beyond it go, oldest first; active ones stay.
	existing := map[netip.Addr]vipEntry{
		netip.MustParseAddr("198.18.1.1"): {Host: "a.example.com"},
		netip.MustParseAddr("198.18.1.2"): {Host: "old.example.com", Retired: true, RetiredAt: testVIPNow.Add(-3 * time.Hour)},
		netip.MustParseAddr("198.18.1.3"): {Host: "mid.example.com", Retired: true, RetiredAt: testVIPNow.Add(-2 * time.Hour)},
		netip.MustParseAddr("198.18.1.4"): {Host: "new.example.com", Retired: true, RetiredAt: testVIPNow.Add(-time.Hour)},
	}
	plan := planVirtualIPs(testVIPRange, hostSet("a.example.com"), existing, testVIPNow, 2)
	want := map[netip.Addr]vipEntry{
		netip.MustParseAddr("198.18.1.1"): existing[netip.MustParseAddr("198.18.1.1")],
		netip.MustParseAddr("198.18.1.4"): existing[netip.MustParseAddr("198.18.1.4")],
	}
	if !reflect.DeepEqual(plan.Entries, want) || len(plan.Released) != 2 {
		t.Fatalf("entries %v, released %v", plan.Entries, plan.Released)
	}
	// Active reservations are never evicted, even beyond capacity.
	active := map[netip.Addr]vipEntry{
		netip.MustParseAddr("198.18.1.1"): {Host: "a.example.com"},
		netip.MustParseAddr("198.18.1.2"): {Host: "b.example.com"},
	}
	if plan := planVirtualIPs(testVIPRange, hostSet("a.example.com", "b.example.com"), active, testVIPNow, 1); len(plan.Entries) != 2 {
		t.Fatalf("active reservations evicted: %v", plan.Entries)
	}
}
