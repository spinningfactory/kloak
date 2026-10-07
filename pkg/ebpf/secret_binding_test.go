package ebpf

import (
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

func TestDescribeBindingEvent(t *testing.T) {
	snapshot := []secrets.Secret{{OwnerID: "ns/api", Key: "token", Shadow: "kl::token-placeholder-0001"}}
	bindings := map[string]podBinding{"uid": {pod: "ns/web", cgroupIDs: []uint64{7}}}
	keys := placeholderKeys(snapshot[0].Shadow)

	for _, k := range keys { // raw and Huffman resolve to the same secret
		pod, secret := describeBindingEvent(secretBindingEvent{CgroupID: 7, Key: k}, bindings, snapshot)
		if pod != "ns/web" || secret != "ns/api[token]" {
			t.Errorf("describeBindingEvent = (%q, %q), want (ns/web, ns/api[token])", pod, secret)
		}
	}
	pod, secret := describeBindingEvent(secretBindingEvent{CgroupID: 9}, bindings, snapshot)
	if pod != "untracked cgroup 9" || secret != "unknown" {
		t.Errorf("unknown event described as (%q, %q)", pod, secret)
	}
}
