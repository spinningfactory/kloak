//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// newVirtualIPMaps creates vip_host_ip and vip_ip_host from spec, pinned
// under opts.PinPath if their spec asks for it. Skips the test when BPF maps
// can't be created (no privileges).
func newVirtualIPMaps(t *testing.T, spec *ciliumebpf.CollectionSpec, opts ciliumebpf.MapOptions) (hostIP, ipHost *ciliumebpf.Map) {
	t.Helper()
	hostIP, err := ciliumebpf.NewMapWithOptions(spec.Maps["vip_host_ip"], opts)
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	ipHost, err = ciliumebpf.NewMapWithOptions(spec.Maps["vip_ip_host"], opts)
	if err != nil {
		_ = hostIP.Close()
		t.Skipf("eBPF maps not available: %v", err)
	}
	return hostIP, ipHost
}

func loadSpec(t *testing.T) *ciliumebpf.CollectionSpec {
	t.Helper()
	spec, err := loadTlsuprobe()
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}
	return spec
}

// entryValues converts entries to their map values, so that comparisons
// don't depend on how a time.Time is represented.
func entryValues(entries map[netip.Addr]vipEntry) map[netip.Addr]vipIPVal {
	out := make(map[netip.Addr]vipIPVal, len(entries))
	for ip, e := range entries {
		out[ip] = vipIPValue(e)
	}
	return out
}

func TestVirtualIPAllocatorSync(t *testing.T) {
	hostIP, ipHost := newVirtualIPMaps(t, loadSpec(t), ciliumebpf.MapOptions{})
	t.Cleanup(func() { _ = hostIP.Close(); _ = ipHost.Close() })
	a := &virtualIPAllocator{hostIP: hostIP, ipHost: ipHost, ranges: testVIPRanges, log: testLog()}

	// want4 / want6: the plans of each family the maps should hold.
	check := func(step string, want4, want6 vipPlan) {
		t.Helper()
		gotHosts, err := readVirtualIPHosts(hostIP)
		if err != nil {
			t.Fatal(err)
		}
		gotEntries, err := readVirtualIPs(ipHost)
		if err != nil {
			t.Fatal(err)
		}
		if wantHosts := vipHostVals(want4.Hosts, want6.Hosts); !reflect.DeepEqual(gotHosts, wantHosts) {
			t.Errorf("%s: vip_host_ip = %v, want %v", step, gotHosts, wantHosts)
		}
		wantEntries := maps.Clone(want4.Entries)
		maps.Copy(wantEntries, want6.Entries)
		if !reflect.DeepEqual(entryValues(gotEntries), entryValues(wantEntries)) {
			t.Errorf("%s: vip_ip_host = %v, want %v", step, gotEntries, wantEntries)
		}
	}

	// Every host gets a fake IP of each family.
	hosts := hostSet("api.example.com", "b.example.com")
	a.sync(hosts, testVIPNow)
	want4, want6 := planVirtualIPRanges(testVIPRanges, hosts, nil, testVIPNow, 4096)
	check("allocate", want4, want6)
	key := vipHostKey("api.example.com")
	var raw vipHostVal
	if err := hostIP.Lookup(&key, &raw); err != nil {
		t.Fatal(err)
	}
	if netip.AddrFrom4(raw.IP4) != want4.Hosts["api.example.com"] || netip.AddrFrom16(raw.IP6) != want6.Hosts["api.example.com"] ||
		!testVIPRange.Contains(netip.AddrFrom4(raw.IP4)) || !testVIPRange6.Contains(netip.AddrFrom16(raw.IP6)) {
		t.Errorf("vip_host_ip value %+v", raw)
	}

	// b is no longer watched: dropped from vip_host_ip, both IPs retired in
	// vip_ip_host.
	later := testVIPNow.Add(time.Minute)
	hosts = hostSet("api.example.com")
	a.sync(hosts, later)
	bIP4, bIP6 := want4.Hosts["b.example.com"], want6.Hosts["b.example.com"]
	delete(want4.Hosts, "b.example.com")
	delete(want6.Hosts, "b.example.com")
	want4.Entries[bIP4] = vipEntry{Host: "b.example.com", Retired: true, RetiredAt: later}
	want6.Entries[bIP6] = vipEntry{Host: "b.example.com", Retired: true, RetiredAt: later}
	check("retire", want4, want6)

	// A second sync with nothing new changes nothing.
	a.sync(hosts, later.Add(time.Minute))
	check("steady", want4, want6)

	// Past the retention period the reservations are released.
	a.sync(hosts, later.Add(virtualIPRetention))
	delete(want4.Entries, bIP4)
	delete(want6.Entries, bIP6)
	check("release", want4, want6)

	// The IPv6 range removed: the hosts keep their fake IPv4, their IPv6
	// reservations go.
	apiIP6 := want6.Hosts["api.example.com"]
	a.ranges = VirtualIPRanges{V4: testVIPRange}
	a.sync(hosts, later.Add(virtualIPRetention))
	check("no IPv6 range", want4, vipPlan{})

	// Back again: the same fake IPv6, derived from the host.
	a.ranges = testVIPRanges
	a.sync(hosts, later.Add(virtualIPRetention))
	if err := hostIP.Lookup(&key, &raw); err != nil {
		t.Fatal(err)
	}
	if got := netip.AddrFrom16(raw.IP6); got != apiIP6 || netip.AddrFrom4(raw.IP4) != want4.Hosts["api.example.com"] {
		t.Errorf("IPv6 range back: vip_host_ip value %+v, want IPv6 %s", raw, apiIP6)
	}
}

func TestVirtualIPAllocatorPrunesUpstreams(t *testing.T) {
	spec := loadSpec(t)
	hostIP, ipHost := newVirtualIPMaps(t, spec, ciliumebpf.MapOptions{})
	t.Cleanup(func() { _ = hostIP.Close(); _ = ipHost.Close() })
	upstream, err := ciliumebpf.NewMap(spec.Maps["vip_upstream"])
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	a := &virtualIPAllocator{hostIP: hostIP, ipHost: ipHost, upstream: upstream, ranges: VirtualIPRanges{V4: testVIPRange}, log: testLog()}

	put := func(ip netip.Addr) {
		t.Helper()
		key := dnsIPKey{IP: ip.As16()}
		var v vipUpstreamVal
		v.Slot[0].IP = netip.MustParseAddr("192.0.2.1").As16()
		if err := upstream.Update(&key, &v, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	has := func(ip netip.Addr) bool {
		t.Helper()
		key := dnsIPKey{IP: ip.As16()}
		var v vipUpstreamVal
		err := upstream.Lookup(&key, &v)
		if err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
			t.Fatal(err)
		}
		return err == nil
	}

	a.sync(hostSet("api.example.com", "b.example.com"), testVIPNow)
	hosts, err := readVirtualIPHosts(hostIP)
	if err != nil {
		t.Fatal(err)
	}
	apiIP, bIP := netip.AddrFrom4(hosts["api.example.com"].IP4), netip.AddrFrom4(hosts["b.example.com"].IP4)
	orphan := netip.MustParseAddr("198.18.200.1")
	for _, ip := range []netip.Addr{apiIP, bIP, orphan} {
		put(ip)
	}

	// b retired: its fake IP still leads to it, and keeps its addresses.
	// An IP reserved for no host loses them.
	later := testVIPNow.Add(time.Minute)
	a.sync(hostSet("api.example.com"), later)
	if !has(apiIP) || !has(bIP) || has(orphan) {
		t.Errorf("after retiring b: api %v, b %v, orphan %v; want true, true, false", has(apiIP), has(bIP), has(orphan))
	}

	// b released: its IP may go to another host, without b's addresses.
	a.sync(hostSet("api.example.com"), later.Add(virtualIPRetention))
	if !has(apiIP) || has(bIP) {
		t.Errorf("after releasing b: api %v, b %v; want true, false", has(apiIP), has(bIP))
	}
}

func TestVirtualIPPinsSurviveReload(t *testing.T) {
	if err := requireBPFFS("/sys/fs/bpf"); err != nil {
		t.Skipf("no bpffs: %v", err)
	}
	pinPath := filepath.Join("/sys/fs/bpf", fmt.Sprintf("kloak-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinPath) })

	open := func() (hostIP, ipHost *ciliumebpf.Map) {
		t.Helper()
		spec := loadSpec(t)
		if err := prepareVirtualIPPins(spec, pinPath, testLog()); err != nil {
			if errors.Is(err, os.ErrPermission) {
				t.Skipf("cannot pin in bpffs: %v", err)
			}
			t.Fatalf("prepareVirtualIPPins: %v", err)
		}
		return newVirtualIPMaps(t, spec, ciliumebpf.MapOptions{PinPath: pinPath})
	}

	hostIP, ipHost := open()
	a := &virtualIPAllocator{hostIP: hostIP, ipHost: ipHost, ranges: testVIPRanges, log: testLog()}
	a.sync(hostSet("api.example.com", "b.example.com"), testVIPNow)
	want, err := readVirtualIPs(ipHost)
	if err != nil || len(want) != 4 {
		t.Fatalf("after sync: %v, %v", want, err)
	}
	_ = hostIP.Close()
	_ = ipHost.Close()

	// A new controller finds the reservations of the previous one.
	hostIP, ipHost = open()
	got, err := readVirtualIPs(ipHost)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entryValues(got), entryValues(want)) {
		t.Fatalf("after reload: %v, want %v", got, want)
	}
	gotHosts, err := readVirtualIPHosts(hostIP)
	if err != nil || len(gotHosts) != 2 {
		t.Fatalf("vip_host_ip after reload: %v, %v", gotHosts, err)
	}
	_ = hostIP.Close()
	_ = ipHost.Close()

	// A pin with another layout (an older kloak's) is replaced, not reused.
	path := filepath.Join(pinPath, "vip_ip_host")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	old, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{Type: ciliumebpf.Hash, KeySize: 16, ValueSize: 8, MaxEntries: 16})
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Pin(path); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()

	hostIP, ipHost = open()
	t.Cleanup(func() { _ = hostIP.Close(); _ = ipHost.Close() })
	if got, err := readVirtualIPs(ipHost); err != nil || len(got) != 0 {
		t.Fatalf("incompatible pin was reused: %v, %v", got, err)
	}
	if ipHost.ValueSize() != uint32(binary.Size(vipIPVal{})) {
		t.Errorf("vip_ip_host value size %d", ipHost.ValueSize())
	}
}

func TestRequireBPFFS(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{dir, filepath.Join(dir, "not", "created")} {
		err := requireBPFFS(p)
		if err == nil || !strings.Contains(err.Error(), "not on a bpffs mount") {
			t.Errorf("requireBPFFS(%s) = %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "not")); !os.IsNotExist(err) {
		t.Error("requireBPFFS created a directory")
	}
}

func TestRemoveVirtualIPPins(t *testing.T) {
	pinPath := filepath.Join(t.TempDir(), "kloak")
	write := func(names ...string) {
		if err := os.MkdirAll(pinPath, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(pinPath, n), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	write(virtualIPMaps...)
	RemoveVirtualIPPins(pinPath, testLog())
	if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
		t.Errorf("pin directory left behind: %v", err)
	}

	// Other pins, and the directory holding them, are left alone.
	write(append([]string{"other"}, virtualIPMaps...)...)
	RemoveVirtualIPPins(pinPath, testLog())
	entries, err := os.ReadDir(pinPath)
	if err != nil || len(entries) != 1 || entries[0].Name() != "other" {
		t.Errorf("pin directory now holds %v (%v)", entries, err)
	}

	// Nothing pinned: nothing to do.
	RemoveVirtualIPPins(filepath.Join(t.TempDir(), "missing"), testLog())
}

// TestVipPodHostBindings checks that vip_pod_host follows the pod bindings:
// granted at bind time, kept for an address that a new pod already holds
// when the old pod is unbound, and pruned to exactly the bindings by a sync.
func TestVipPodHostBindings(t *testing.T) {
	objs := loadTestObjects(t)
	m := &TLSUprobeManager{
		objs:       objs,
		log:        zap.NewNop().Sugar(),
		bindings:   make(map[string]podBinding),
		virtualIPs: &virtualIPAllocator{},
		lastSnapshot: []secrets.Secret{
			{OwnerID: "ns/api", Key: "token", Shadow: "kl::token-placeholder-0001", Host: "api.example.com"},
			{OwnerID: "ns/db", Key: "password", Shadow: "kl::db-placeholder-000003", Host: "db.example.com"},
		},
	}
	read := func() []string {
		t.Helper()
		got := make(map[vipPodHostKey]struct{})
		var k vipPodHostKey
		var v uint8
		iter := objs.VipPodHost.Iterate()
		for iter.Next(&k, &v) {
			got[k] = struct{}{}
		}
		if err := iter.Err(); err != nil {
			t.Fatal(err)
		}
		return vipPodHostStrings(got)
	}
	check := func(step string, want ...string) {
		t.Helper()
		if got := read(); !slices.Equal(got, want) {
			t.Errorf("%s: vip_pod_host = %q, want %q", step, got, want)
		}
	}

	// The addresses (a dual-stack pod's) went to a new pod before the old
	// pod's deletion was seen.
	addr := []netip.Addr{netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("fd42::7")}
	m.BindPodSecrets("uid-old", "ns/old", addr, nil, []secrets.Ref{{OwnerID: "ns/api"}})
	m.BindPodSecrets("uid-new", "ns/new", addr, nil, []secrets.Ref{{OwnerID: "ns/db"}})
	check("bound", "10.42.0.7 api.example.com", "10.42.0.7 db.example.com", "fd42::7 api.example.com", "fd42::7 db.example.com")
	m.UnbindPod("uid-old")
	check("old pod unbound", "10.42.0.7 db.example.com", "fd42::7 db.example.com")

	putPodHost(t, objs, netip.MustParseAddr("10.42.0.99"), "api.example.com")
	syncVipPodHost(objs.VipPodHost, vipPodHosts(m.lastSnapshot, m.bindings, false), m.log)
	check("synced", "10.42.0.7 db.example.com", "fd42::7 db.example.com")

	m.SetSecretBindingMode(SecretBindingAudit)
	m.BindPodSecrets("uid-new", "ns/new", addr, nil, []secrets.Ref{{OwnerID: "ns/db"}})
	syncVipPodHost(objs.VipPodHost, vipPodHosts(m.lastSnapshot, m.bindings, true), m.log)
	check("audit", "10.42.0.7 ", "fd42::7 ")
}

// TestBindPodNetworkKeepsCgroups checks that binding a pod's network (its
// sandbox being created, NRI) keeps the container cgroups of its current
// binding, which a sync would otherwise revoke.
func TestBindPodNetworkKeepsCgroups(t *testing.T) {
	objs := loadTestObjects(t)
	m := &TLSUprobeManager{
		objs:       objs,
		log:        zap.NewNop().Sugar(),
		bindings:   make(map[string]podBinding),
		virtualIPs: &virtualIPAllocator{},
		lastSnapshot: []secrets.Secret{
			{OwnerID: "ns/api", Key: "token", Shadow: "kl::token-placeholder-0001", Host: "api.example.com"},
		},
	}
	refs := []secrets.Ref{{OwnerID: "ns/api"}}
	aclCgroups := func() []uint64 {
		t.Helper()
		var out []uint64
		var k secretACLKey
		var v uint8
		iter := objs.SecretAcl.Iterate()
		for iter.Next(&k, &v) {
			out = append(out, k.CgroupID)
		}
		if err := iter.Err(); err != nil {
			t.Fatal(err)
		}
		slices.Sort(out)
		return slices.Compact(out)
	}

	// A new pod: its network only, no cgroup yet.
	m.BindPodNetwork("uid", "ns/app", []netip.Addr{netip.MustParseAddr("10.42.0.7")}, refs)
	if b := m.bindings["uid"]; len(b.cgroupIDs) != 0 || len(b.podIPs) != 1 {
		t.Fatalf("binding %+v", b)
	}

	// Running: the reconciler binds its containers; a container created
	// later (a restart) rebinds the network at a new address.
	m.BindPodSecrets("uid", "ns/app", []netip.Addr{netip.MustParseAddr("10.42.0.7")}, []uint64{41, 42}, refs)
	m.BindPodNetwork("uid", "ns/app", []netip.Addr{netip.MustParseAddr("10.42.0.8")}, refs)
	if b := m.bindings["uid"]; !slices.Equal(b.cgroupIDs, []uint64{41, 42}) || b.podIPs[0] != netip.MustParseAddr("10.42.0.8") {
		t.Fatalf("binding after BindPodNetwork: %+v", b)
	}
	syncSecretACL(objs.SecretAcl, m.lastSnapshot, m.bindings, m.log)
	if got := aclCgroups(); !slices.Equal(got, []uint64{41, 42}) {
		t.Errorf("secret_acl cgroups after a sync: %v, want [41 42]", got)
	}
	syncVipPodHost(objs.VipPodHost, vipPodHosts(m.lastSnapshot, m.bindings, false), m.log)
	var k vipPodHostKey
	var v uint8
	var hosts []string
	iter := objs.VipPodHost.Iterate()
	for iter.Next(&k, &v) {
		hosts = append(hosts, netip.AddrFrom16(k.PodIP).Unmap().String())
	}
	if !slices.Equal(hosts, []string{"10.42.0.8"}) {
		t.Errorf("vip_pod_host addresses %v, want the new address only", hosts)
	}
}

// TestAttachPodDNSRewriteNetns attaches tc_dns_rewrite in a network
// namespace given by path, as the container runtime reports it while it
// creates a pod sandbox (NRI), before the pod has any process.
func TestAttachPodDNSRewriteNetns(t *testing.T) {
	objs := loadTestObjects(t)
	podNS := newNetns(t)
	h, err := netlink.NewHandleAt(netns.NsHandle(podNS.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	// The pod's interface, with its address and the default route through
	// it, as a CNI leaves it.
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}
	if err := h.LinkAdd(link); err != nil {
		t.Skipf("cannot create a dummy interface: %v", err)
	}
	if err := h.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	addr, _ := netlink.ParseAddr("10.42.0.7/24")
	if err := h.AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}
	if err := h.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: net.ParseIP("10.42.0.1")}); err != nil {
		t.Fatal(err)
	}

	m := &TLSUprobeManager{
		objs:             objs,
		log:              zap.NewNop().Sugar(),
		virtualIPs:       &virtualIPAllocator{},
		tcMode:           newTCModeResolver(TCAttachAuto),
		dnsRewrite:       make(map[string]*dnsRewriteAttach),
		dnsRewriteFailed: make(map[string]bool),
	}
	t.Cleanup(func() { m.DetachPodDNSRewrite("uid") })
	path := fmt.Sprintf("/proc/self/fd/%d", podNS.Fd())
	want := []netip.Addr{netip.MustParseAddr("10.42.0.7")}
	got, err := m.AttachPodDNSRewriteNetns("uid", "ns/app", path)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("addresses %v, want %v", got, want)
	}
	a := m.dnsRewrite["uid"]
	if a == nil || len(a.links) != 1 {
		t.Fatalf("attachment %+v", a)
	}
	// Again (another container of the pod, or the reconciler polling): the
	// same attachment.
	if got, err := m.AttachPodDNSRewriteNetns("uid", "ns/app", path); err != nil || !slices.Equal(got, want) || m.dnsRewrite["uid"] != a {
		t.Errorf("second attach: %v, %v, same attachment %v", got, err, m.dnsRewrite["uid"] == a)
	}
	// The host's network namespace (a host-network pod): nothing.
	if got, err := m.AttachPodDNSRewriteNetns("uid-host", "ns/host", "/proc/1/ns/net"); err != nil || got != nil || m.dnsRewrite["uid-host"] != nil {
		t.Errorf("host netns: %v, %v", got, err)
	}
	if _, err := m.AttachPodDNSRewriteNetns("uid-gone", "ns/gone", "/proc/self/fd/9999"); err == nil {
		t.Error("attached through a path that does not exist")
	}
}
