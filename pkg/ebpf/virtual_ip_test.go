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

func TestParseVirtualIPRange(t *testing.T) {
	if got, err := ParseVirtualIPRange(DefaultVirtualIPRange); err != nil || got != netip.MustParsePrefix("198.18.0.0/15") {
		t.Fatalf("default range: %v, %v", got, err)
	}
	if _, err := ParseVirtualIPRange("10.200.0.0/19"); err != nil {
		t.Errorf("/19: %v", err)
	}
	for _, bad := range []string{
		"",
		"198.18.0.0",        // not a prefix
		"198.18.1.0/15",     // host bits set
		"10.200.0.0/20",     // too small
		"fd00:6b6c::/64",    // IPv6
		"::ffff:0.0.0.0/96", // IPv4-mapped IPv6
	} {
		if _, err := ParseVirtualIPRange(bad); err == nil {
			t.Errorf("ParseVirtualIPRange(%q) succeeded", bad)
		}
	}
}

func TestHostResolutionConfigValidate(t *testing.T) {
	ok := []HostResolutionConfig{
		{},
		{Mode: HostResolutionDNSSnoop},
		{Mode: HostResolutionVirtualIP, VirtualIPRange: netip.MustParsePrefix(DefaultVirtualIPRange)},
	}
	for _, c := range ok {
		if err := c.validate(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	bad := []HostResolutionConfig{
		{Mode: "stub"},
		{Mode: HostResolutionVirtualIP},
		{Mode: HostResolutionVirtualIP, VirtualIPRange: netip.MustParsePrefix("10.0.0.0/24")},
	}
	for _, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("%+v: validated", c)
		}
	}
	if got := (HostResolutionConfig{}).pinPath(); got != DefaultBPFPinPath {
		t.Errorf("default pin path %q", got)
	}
}

func TestCheckVirtualIPRange(t *testing.T) {
	r := netip.MustParsePrefix(DefaultVirtualIPRange)
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

func TestHostRoutes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := routeTable([3]string{"cni0", "10.42.0.0", "255.255.255.0"})
	if err := os.WriteFile(filepath.Join(dir, "net", "route"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := HostRoutes(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []ReservedRange{{Prefix: netip.MustParsePrefix("10.42.0.0/24"), Source: "node route via cni0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HostRoutes = %v, want %v", got, want)
	}
	if _, err := HostRoutes(filepath.Join(dir, "missing")); err == nil {
		t.Error("HostRoutes on a missing directory succeeded")
	}
}

var (
	testVIPRange = netip.MustParsePrefix(DefaultVirtualIPRange)
	testVIPNow   = time.Unix(1_800_000_000, 0)
)

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
