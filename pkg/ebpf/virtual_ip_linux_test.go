//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
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
	a := &virtualIPAllocator{hostIP: hostIP, ipHost: ipHost, prefix: testVIPRange, log: testLog()}

	check := func(step string, want vipPlan) {
		t.Helper()
		gotHosts, err := readVirtualIPHosts(hostIP)
		if err != nil {
			t.Fatal(err)
		}
		gotEntries, err := readVirtualIPs(ipHost)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotHosts, want.Hosts) {
			t.Errorf("%s: vip_host_ip = %v, want %v", step, gotHosts, want.Hosts)
		}
		if !reflect.DeepEqual(entryValues(gotEntries), entryValues(want.Entries)) {
			t.Errorf("%s: vip_ip_host = %v, want %v", step, gotEntries, want.Entries)
		}
	}

	hosts := hostSet("api.example.com", "b.example.com")
	a.sync(hosts, testVIPNow)
	want := planVirtualIPs(testVIPRange, hosts, nil, testVIPNow, 4096)
	check("allocate", want)

	// The IPv6 half stays zero until an IPv6 range is supported.
	key := vipHostKey("api.example.com")
	var raw vipHostVal
	if err := hostIP.Lookup(&key, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.IP6 != [16]byte{} || netip.AddrFrom4(raw.IP4) != want.Hosts["api.example.com"] {
		t.Errorf("vip_host_ip value %+v", raw)
	}

	// b is no longer watched: dropped from vip_host_ip, retired in vip_ip_host.
	later := testVIPNow.Add(time.Minute)
	hosts = hostSet("api.example.com")
	a.sync(hosts, later)
	bIP := want.Hosts["b.example.com"]
	want.Hosts = map[string]netip.Addr{"api.example.com": want.Hosts["api.example.com"]}
	want.Entries[bIP] = vipEntry{Host: "b.example.com", Retired: true, RetiredAt: later}
	check("retire", want)

	// A second sync with nothing new changes nothing.
	a.sync(hosts, later.Add(time.Minute))
	check("steady", want)

	// Past the retention period the reservation is released.
	a.sync(hosts, later.Add(virtualIPRetention))
	delete(want.Entries, bIP)
	check("release", want)
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
	a := &virtualIPAllocator{hostIP: hostIP, ipHost: ipHost, prefix: testVIPRange, log: testLog()}
	a.sync(hostSet("api.example.com", "b.example.com"), testVIPNow)
	want, err := readVirtualIPs(ipHost)
	if err != nil || len(want) != 2 {
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
