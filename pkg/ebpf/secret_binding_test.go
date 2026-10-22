package ebpf

import (
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

func TestParseSecretBindingMode(t *testing.T) {
	for in, want := range map[string]SecretBindingMode{
		"":        SecretBindingEnforce,
		"enforce": SecretBindingEnforce,
		" AUDIT ": SecretBindingAudit,
		"Enforce": SecretBindingEnforce,
		"audit":   SecretBindingAudit,
	} {
		got, err := ParseSecretBindingMode(in)
		if err != nil || got != want {
			t.Errorf("ParseSecretBindingMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseSecretBindingMode("off"); err == nil {
		t.Error(`ParseSecretBindingMode("off") succeeded; binding can't be disabled`)
	}
	if SecretBindingEnforce.bpfValue() != 0 {
		t.Error("enforce must be the BPF map's zero value so an unwritten map enforces")
	}
}

// placeholderKeys must produce the same keys syncSecrets writes to
// secret_map, or bound pods would be refused.
func TestPlaceholderKeysMatchSecretMap(t *testing.T) {
	shadow := "kl::Oh,t*jO0*Z051;bQcysFh4"
	keys := placeholderKeys(shadow)
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want raw + Huffman", len(keys))
	}
	if string(keys[0][:]) != shadow[:secrets.ShadowPrefixLen] {
		t.Errorf("raw key = %q, want %q", keys[0][:], shadow[:secrets.ShadowPrefixLen])
	}
	huff := hpack.AppendHuffmanString(nil, shadow)
	if string(keys[1][:]) != string(huff[:secrets.ShadowPrefixLen]) {
		t.Errorf("Huffman key = %x, want %x", keys[1][:], huff[:secrets.ShadowPrefixLen])
	}
	if placeholderKeys("kl::abc") != nil {
		t.Error("a shadow shorter than the BPF key must yield no keys")
	}
}

func TestSecretACL(t *testing.T) {
	snapshot := []secrets.Secret{
		{OwnerID: "ns/api", Key: "token", Shadow: "kl::token-placeholder-0001"},
		{OwnerID: "ns/api", Key: "id", Shadow: "kl::id-placeholder-000002"},
		{OwnerID: "ns/db", Key: "password", Shadow: "kl::db-placeholder-000003"},
	}
	keysOf := func(owner, key string) []placeholderKey {
		for _, s := range snapshot {
			if s.OwnerID == owner && s.Key == key {
				return placeholderKeys(s.Shadow)
			}
		}
		t.Fatalf("no snapshot entry %s[%s]", owner, key)
		return nil
	}
	bindings := map[string]podBinding{
		"uid-all":     {pod: "ns/all", cgroupIDs: []uint64{1, 2}, refs: []secrets.Ref{{OwnerID: "ns/api"}}},
		"uid-token":   {pod: "ns/token", cgroupIDs: []uint64{3}, refs: []secrets.Ref{{OwnerID: "ns/api", Keys: []string{"token"}}}},
		"uid-unknown": {pod: "ns/unknown", cgroupIDs: []uint64{4}, refs: []secrets.Ref{{OwnerID: "ns/gone"}, {OwnerID: "ns/api", Keys: []string{"nope"}}}},
		"uid-none":    {pod: "ns/none", cgroupIDs: []uint64{5}},
	}

	acl := secretACL(snapshot, bindings)

	want := make(map[secretACLKey]struct{})
	for _, cg := range []uint64{1, 2} {
		for _, k := range append(keysOf("ns/api", "token"), keysOf("ns/api", "id")...) {
			want[secretACLKey{CgroupID: cg, Key: k}] = struct{}{}
		}
	}
	for _, k := range keysOf("ns/api", "token") {
		want[secretACLKey{CgroupID: 3, Key: k}] = struct{}{}
	}
	if len(acl) != len(want) {
		t.Errorf("got %d entries, want %d", len(acl), len(want))
	}
	for k := range want {
		if _, ok := acl[k]; !ok {
			t.Errorf("missing grant cgroup=%d key=%q", k.CgroupID, k.Key[:])
		}
	}
	for _, db := range keysOf("ns/db", "password") {
		for cg := uint64(1); cg <= 5; cg++ {
			if _, ok := acl[secretACLKey{CgroupID: cg, Key: db}]; ok {
				t.Errorf("cgroup %d was granted ns/db, which no pod references", cg)
			}
		}
	}
}

func TestVipPodHosts(t *testing.T) {
	snapshot := []secrets.Secret{
		{OwnerID: "ns/api", Key: "token", Shadow: "kl::token-placeholder-0001", Host: "api.example.com"},
		{OwnerID: "ns/api", Key: "id", Shadow: "kl::id-placeholder-000002"}, // any host
		{OwnerID: "ns/db", Key: "password", Shadow: "kl::db-placeholder-000003", Host: "db.example.com"},
		{OwnerID: "ns/db", Key: "user", Shadow: "kl::db-placeholder-000004", Host: "users.example.com"},
		{OwnerID: "ns/ip", Key: "key", Shadow: "kl::ip-placeholder-000005", IP: net.ParseIP("192.0.2.1")},
		{OwnerID: "ns/long", Key: "key", Shadow: "kl::long-placeholder-0006", Host: strings.Repeat("a", maxHostLen)},
	}
	ip := netip.MustParseAddr
	bindings := map[string]podBinding{
		// Both addresses of a dual-stack pod.
		"uid-api":     {podIPs: []netip.Addr{ip("10.42.0.7"), ip("fd00::7")}, refs: []secrets.Ref{{OwnerID: "ns/api"}}},
		"uid-db-key":  {podIPs: []netip.Addr{ip("::ffff:10.42.0.8")}, refs: []secrets.Ref{{OwnerID: "ns/db", Keys: []string{"password"}}}},
		"uid-pending": {refs: []secrets.Ref{{OwnerID: "ns/api"}}}, // no address yet
		"uid-ip":      {podIPs: []netip.Addr{ip("10.42.0.9")}, refs: []secrets.Ref{{OwnerID: "ns/ip"}, {OwnerID: "ns/long"}}},
		"uid-unknown": {podIPs: []netip.Addr{ip("10.42.0.10")}, refs: []secrets.Ref{{OwnerID: "ns/gone"}, {OwnerID: "ns/db", Keys: []string{"nope"}}}},
	}
	key := func(addr, host string) vipPodHostKey {
		k := vipPodHostKey{PodIP: ip(addr).As16()}
		copy(k.Host[:], host)
		return k
	}

	for _, c := range []struct {
		name    string
		anyHost bool
		want    []vipPodHostKey
	}{
		{"enforce", false, []vipPodHostKey{
			key("10.42.0.7", "api.example.com"),
			key("fd00::7", "api.example.com"),
			key("10.42.0.8", "db.example.com"),
		}},
		{"audit", true, []vipPodHostKey{
			key("10.42.0.7", ""), key("fd00::7", ""), key("10.42.0.8", ""), key("10.42.0.9", ""), key("10.42.0.10", ""),
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := vipPodHosts(snapshot, bindings, c.anyHost)
			want := make(map[vipPodHostKey]struct{}, len(c.want))
			for _, k := range c.want {
				want[k] = struct{}{}
			}
			if !maps.Equal(got, want) {
				t.Errorf("got %v, want %v", vipPodHostStrings(got), vipPodHostStrings(want))
			}
		})
	}
}

func vipPodHostStrings(m map[vipPodHostKey]struct{}) []string {
	var out []string
	for k := range m {
		out = append(out, netip.AddrFrom16(k.PodIP).Unmap().String()+" "+strings.TrimRight(string(k.Host[:]), "\x00"))
	}
	slices.Sort(out)
	return out
}

func TestDescribeBindingEvent(t *testing.T) {
	snapshot := []secrets.Secret{{OwnerID: "ns/api", Key: "token", Shadow: "kl::token-placeholder-0001"}}
	bindings := map[string]podBinding{"uid": {pod: "ns/web", cgroupIDs: []uint64{7}}}
	keys := placeholderKeys(snapshot[0].Shadow)

	for _, k := range keys { // raw and Huffman resolve to the same secret
		pod, secret := describeBindingEvent(&secretBindingEvent{CgroupID: 7, Key: k}, bindings, snapshot)
		if pod != "ns/web" || secret != "ns/api[token]" {
			t.Errorf("describeBindingEvent = (%q, %q), want (ns/web, ns/api[token])", pod, secret)
		}
	}
	pod, secret := describeBindingEvent(&secretBindingEvent{CgroupID: 9}, bindings, snapshot)
	if pod != "untracked cgroup 9" || secret != "unknown" {
		t.Errorf("unknown event described as (%q, %q)", pod, secret)
	}
}
