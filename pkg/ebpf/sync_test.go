//go:build linux

package ebpf

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/spinningfactory/kloak/pkg/secrets"
	k8ssecrets "github.com/spinningfactory/kloak/pkg/secrets/k8s"
)

// k8sSource wraps a controller-runtime fake client as a secrets.Source so
// the existing k8s-shaped fixtures keep driving syncSecrets. The adapter
// itself has its own unit tests in pkg/secrets/k8s; here we just want the
// "k8s state → BPF map" integration coverage.
func k8sSource(reader client.Reader) *k8ssecrets.Source {
	return k8ssecrets.NewSource(reader)
}

// createTestMap creates the map name of the BPF objects on its own, with
// their layout.
func createTestMap(t *testing.T, name string) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(loadSpec(t).Maps[name].Copy())
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func createTestSecretMap(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	return createTestMap(t, "secret_map")
}

func testLog() *zap.SugaredLogger {
	return zap.NewNop().Sugar()
}

func newFakeClient(objs ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

// enabledSecret creates an enabled secret with the given data keys/values.
func enabledSecret(name, ns string, data map[string][]byte, labels map[string]string, annotations map[string]string) *corev1.Secret {
	l := map[string]string{"getkloak.io/enabled": "true"}
	for k, v := range labels {
		l[k] = v
	}
	a := map[string]string{}
	for k, v := range annotations {
		a[k] = v
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Labels:      l,
			Annotations: a,
		},
		Data: data,
	}
}

// shadowSecret creates a shadow secret with the given data keys/values.
func shadowSecret(name, ns, ownerName string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"getkloak.io/managed": "true",
				"getkloak.io/owner":   ownerName,
			},
		},
		Data: data,
	}
}

func TestSyncSecrets_BasicSync(t *testing.T) {
	m := createTestSecretMap(t)
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("my-real-secret-value!")}, nil, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kl::abcd1234-5678-9abc")}),
	)

	if err := syncSecrets(context.Background(), m, k8sSource(reader), testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	// Verify the key was stored (first 8 bytes of shadow prefix)
	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found in map: %v", err)
	}

	if val.Len != 21 {
		t.Errorf("expected len=21, got %d", val.Len)
	}
	got := string(val.RealSecret[:val.Len])
	if got != "my-real-secret-value!" {
		t.Errorf("expected real secret 'my-real-secret-value!', got %q", got)
	}
}

func TestSyncSecrets_MinLength(t *testing.T) {
	m := createTestSecretMap(t)
	// Shadow value "kl::" is 4 bytes, below 8-byte minimum
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("short")}, nil, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kl::")}),
	)

	if err := syncSecrets(context.Background(), m, k8sSource(reader), testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	// Map should be empty — secret was too short
	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	if err := m.Lookup(&key, &val); err == nil {
		t.Error("short secret should not be stored in BPF map")
	}
}

func TestSyncSecrets_Truncation(t *testing.T) {
	m := createTestSecretMap(t)
	longValue := strings.Repeat("A", 200)
	longShadow := "kl::abcd1234-5678-9abc-def0-123456789abc" + strings.Repeat(" ", 158)
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte(longValue)}, nil, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte(longShadow)}),
	)

	if err := syncSecrets(context.Background(), m, k8sSource(reader), testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found in map: %v", err)
	}

	if val.Len != 128 {
		t.Errorf("expected truncated len=128, got %d", val.Len)
	}
}

func TestSyncSecrets_HostFilter(t *testing.T) {
	m := createTestSecretMap(t)
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("my-real-secret-value!")},
			nil, map[string]string{"getkloak.io/hosts": "api.stripe.com"}),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kl::abcd1234-5678-9abc")}),
	)

	if err := syncSecrets(context.Background(), m, k8sSource(reader), testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found in map: %v", err)
	}

	if val.HostLen != 14 {
		t.Errorf("expected hostLen=14, got %d", val.HostLen)
	}
	gotHost := string(val.AllowedHost[:val.HostLen])
	if gotHost != "api.stripe.com" {
		t.Errorf("expected host 'api.stripe.com', got %q", gotHost)
	}
}

func TestSyncSecrets_WildcardHost(t *testing.T) {
	m := createTestSecretMap(t)
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("my-real-secret-value!")},
			nil, map[string]string{"getkloak.io/hosts": "*"}),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kl::abcd1234-5678-9abc")}),
	)

	if err := syncSecrets(context.Background(), m, k8sSource(reader), testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found in map: %v", err)
	}

	if val.HostLen != 0 {
		t.Errorf("wildcard host should have hostLen=0, got %d", val.HostLen)
	}
}

func TestSyncSecrets_StaleEntryPruning(t *testing.T) {
	m := createTestSecretMap(t)

	// First sync: add a secret
	reader1 := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("my-real-secret-value!")}, nil, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kl::abcd1234-5678-9abc")}),
	)
	if err := syncSecrets(context.Background(), m, k8sSource(reader1), testLog()); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}

	// Verify it exists
	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found after first sync: %v", err)
	}

	// Remove the enabled secret (simulate deletion) and sync again with empty client
	reader2 := newFakeClient()
	if err := syncSecrets(context.Background(), m, k8sSource(reader2), testLog()); err != nil {
		t.Fatalf("second sync failed: %v", err)
	}

	// Should be pruned
	if err := m.Lookup(&key, &val); err == nil {
		t.Error("stale entry should have been pruned from BPF map")
	}
}

func TestSyncSecrets_Update(t *testing.T) {
	m := createTestSecretMap(t)

	// Initial value
	reader1 := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("old-secret-value-here")}, nil, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kl::abcd1234-5678-9abc")}),
	)
	if err := syncSecrets(context.Background(), m, k8sSource(reader1), testLog()); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}

	// Update value (same shadow, different real value)
	reader2 := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("new-secret-value-here")}, nil, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kl::abcd1234-5678-9abc")}),
	)
	if err := syncSecrets(context.Background(), m, k8sSource(reader2), testLog()); err != nil {
		t.Fatalf("second sync failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found: %v", err)
	}

	got := string(val.RealSecret[:val.Len])
	if got != "new-secret-value-here" {
		t.Errorf("expected updated value 'new-secret-value-here', got %q", got)
	}
}

func TestSyncSecrets_FullPrefix(t *testing.T) {
	m := createTestSecretMap(t)
	// Longer than the 42 bytes stored for verification.
	shadow := "kl::abcd1234-5678-9abc-def0-123456789abc-0123"
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte(shadow)}, nil, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte(shadow)}),
	)

	if err := syncSecrets(context.Background(), m, k8sSource(reader), testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found: %v", err)
	}

	if val.PrefixLen != 42 {
		t.Errorf("expected prefixLen=42, got %d", val.PrefixLen)
	}
	gotPrefix := string(val.FullPrefix[:val.PrefixLen])
	if gotPrefix != shadow[:42] {
		t.Errorf("expected prefix %q, got %q", shadow[:42], gotPrefix)
	}
}

// TestApplySecrets_WatchedHosts checks the hosts applySecrets returns, which
// the virtual IP allocator gives fake IPs: those the synced secrets are
// restricted to, and no more once the secrets are gone.
func TestApplySecrets_WatchedHosts(t *testing.T) {
	m := createTestSecretMap(t)
	reader := newFakeClient(
		enabledSecret("secret1", "default",
			map[string][]byte{"api-key": []byte("my-real-secret-value!")},
			nil, map[string]string{"getkloak.io/hosts": "api.stripe.com"}),
		shadowSecret("secret1-kloak", "default", "secret1",
			map[string][]byte{"api-key": []byte("kl::abcd1234-5678-9abc")}),
		enabledSecret("secret2", "default",
			map[string][]byte{"api-key": []byte("another-secret-value!")},
			nil, map[string]string{"getkloak.io/hosts": "api.github.com"}),
		shadowSecret("secret2-kloak", "default", "secret2",
			map[string][]byte{"api-key": []byte("kl::efgh5678-1234-5678")}),
		enabledSecret("secret3", "default",
			map[string][]byte{"api-key": []byte("ip-restricted-value!!")},
			nil, map[string]string{"getkloak.io/hosts": "10.0.0.5"}),
		shadowSecret("secret3-kloak", "default", "secret3",
			map[string][]byte{"api-key": []byte("kl::ijkl9012-3456-7890")}),
	)
	snapshot, err := k8sSource(reader).Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	want := map[string]struct{}{"api.stripe.com": {}, "api.github.com": {}}
	if got, err := applySecrets(m, snapshot, testLog()); err != nil || !maps.Equal(got, want) {
		t.Errorf("hosts = %v, %v, want %v", got, err, want)
	}
	if got, err := applySecrets(m, nil, testLog()); err != nil || len(got) != 0 {
		t.Errorf("hosts after the secrets went = %v, %v, want none", got, err)
	}
}

func TestSyncSecrets_IPFilter(t *testing.T) {
	m := createTestSecretMap(t)
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("my-real-secret-value!")},
			nil, map[string]string{"getkloak.io/hosts": "192.168.1.1"}),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kl::abcd1234-5678-9abc")}),
	)

	if err := syncSecrets(context.Background(), m, k8sSource(reader), testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found in map: %v", err)
	}

	// IP filtering should be active (IpLen == 16)
	if val.IpLen != 16 {
		t.Errorf("expected ipLen=16 for IP filter, got %d", val.IpLen)
	}

	// HostLen should be 0 since we're using IP filter
	if val.HostLen != 0 {
		t.Errorf("expected hostLen=0 for IP filter, got %d", val.HostLen)
	}

	// Verify the IP is stored correctly (IPv4-mapped-IPv6: ::ffff:192.168.1.1)
	// 192.168.1.1 in big-endian: 0xC0A80101
	// IPv4-mapped-IPv6: ::ffff:0:C0A80101
	expectedIP := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01}
	gotIP := val.AllowedIp[:16]
	for i := 0; i < 16; i++ {
		if gotIP[i] != expectedIP[i] {
			t.Errorf("expected IP byte %d to be 0x%02x, got 0x%02x", i, expectedIP[i], gotIP[i])
		}
	}
}

func TestSyncSecrets_IPv6Filter(t *testing.T) {
	m := createTestSecretMap(t)
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("my-real-secret-value!")},
			nil, map[string]string{"getkloak.io/hosts": "2001:db8::1"}),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kl::abcd1234-5678-9abc")}),
	)

	if err := syncSecrets(context.Background(), m, k8sSource(reader), testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kl::abcd"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found in map: %v", err)
	}

	if val.IpLen != 16 {
		t.Errorf("expected ipLen=16 for IP filter, got %d", val.IpLen)
	}

	if val.HostLen != 0 {
		t.Errorf("expected hostLen=0 for IP filter, got %d", val.HostLen)
	}

	// Verify the IPv6 is stored correctly
	// 2001:db8::1 -> 2001 0db8 0000 0000 0000 0000 0000 0001
	expectedIP := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	gotIP := val.AllowedIp[:16]
	for i := 0; i < 16; i++ {
		if gotIP[i] != expectedIP[i] {
			t.Errorf("expected IP byte %d to be 0x%02x, got 0x%02x", i, expectedIP[i], gotIP[i])
		}
	}
}

func TestSyncSecrets_NilReader(t *testing.T) {
	m := createTestSecretMap(t)
	// syncSecrets should return nil when reader is nil
	if err := syncSecrets(context.Background(), m, nil, testLog()); err != nil {
		t.Fatalf("syncSecrets with nil reader should not error: %v", err)
	}
}

func createTestSecretACLMap(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type:       ciliumebpf.Hash,
		KeySize:    16, // struct secret_acl_key
		ValueSize:  1,
		MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func aclEntries(t *testing.T, m *ciliumebpf.Map) map[secretACLKey]struct{} {
	t.Helper()
	out := make(map[secretACLKey]struct{})
	var k secretACLKey
	var v uint8
	iter := m.Iterate()
	for iter.Next(&k, &v) {
		out[k] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate secret_acl: %v", err)
	}
	return out
}

func TestSyncSecretACL_GrantsAndPrunes(t *testing.T) {
	m := createTestSecretACLMap(t)
	snapshot := []secrets.Secret{
		{OwnerID: "ns/api", Key: "token", Shadow: "kl::token-placeholder-0001"},
		{OwnerID: "ns/db", Key: "password", Shadow: "kl::db-placeholder-000003"},
	}
	bindings := map[string]podBinding{
		"a": {pod: "ns/a", cgroupIDs: []uint64{1}, refs: []secrets.Ref{{OwnerID: "ns/api"}}},
		"b": {pod: "ns/b", cgroupIDs: []uint64{2}, refs: []secrets.Ref{{OwnerID: "ns/db"}}},
	}

	if err := syncSecretACL(m, snapshot, bindings, testLog()); err != nil {
		t.Fatal(err)
	}
	if got, want := aclEntries(t, m), secretACL(snapshot, bindings); len(got) != len(want) {
		t.Fatalf("after first sync: %d entries, want %d", len(got), len(want))
	}

	// Pod b goes away: its grants must be pruned, pod a's kept.
	delete(bindings, "b")
	if err := syncSecretACL(m, snapshot, bindings, testLog()); err != nil {
		t.Fatal(err)
	}
	got := aclEntries(t, m)
	for k := range got {
		if k.CgroupID == 2 {
			t.Errorf("stale grant for removed pod survived: %q", k.Key[:])
		}
	}
	for k := range secretACL(snapshot, bindings) {
		if _, ok := got[k]; !ok {
			t.Errorf("grant for remaining pod lost: cgroup=%d", k.CgroupID)
		}
	}
}

// TestApplySecrets_ReportsFailedWrites checks that a write secret_map
// refuses (it is full) is reported once the other writes are done, so that
// the sync is retried.
func TestApplySecrets_ReportsFailedWrites(t *testing.T) {
	spec := loadSpec(t).Maps["secret_map"].Copy()
	spec.MaxEntries = 1
	m, err := ciliumebpf.NewMap(spec)
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	// The secret takes two entries, one for its placeholder and one for
	// its HPACK-Huffman encoding: the second does not fit.
	snapshot := []secrets.Secret{{OwnerID: "ns/api", Key: "token", Real: "real-token-value-0001", Shadow: "kl::token-placeholder-0001"}}
	_, err = applySecrets(m, snapshot, testLog())
	if err == nil || !strings.Contains(err.Error(), "secret_map: 1 failed map operations") {
		t.Fatalf("applySecrets error = %v, want one failed secret_map operation", err)
	}
	var key secretKey
	copy(key.Prefix[:], "kl::toke")
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Errorf("the placeholder's entry, written before the failure: %v", err)
	}
}

// errSource is a secrets.Source whose snapshots fail.
type errSource struct{ err error }

func (s errSource) Snapshot(context.Context) ([]secrets.Secret, error) { return nil, s.err }

// TestSyncSecrets_Manager checks that SyncSecrets fills secret_map, the
// virtual IP of the secret's host and the pod bindings, and that a failed
// snapshot is reported and leaves the maps as they were.
func TestSyncSecrets_Manager(t *testing.T) {
	objs := loadTestObjects(t)
	ranges, err := ParseVirtualIPRanges(DefaultVirtualIPRange)
	if err != nil {
		t.Fatal(err)
	}
	reader := newFakeClient(
		enabledSecret("api", "ns", map[string][]byte{"token": []byte("real-token-value-0001")}, nil,
			map[string]string{"getkloak.io/hosts": "api.example.com"}),
		shadowSecret("api-kloak", "ns", "api", map[string][]byte{"token": []byte("kl::token-placeholder-0001")}),
	)
	m := &TLSUprobeManager{
		objs:         objs,
		log:          testLog(),
		secretSource: k8sSource(reader),
		bindings: map[string]podBinding{
			"uid": {pod: "ns/app", cgroupIDs: []uint64{41}, refs: []secrets.Ref{{OwnerID: "ns/api"}}},
		},
		virtualIPs: newVirtualIPAllocator(objs, ranges, testLog()),
	}

	if err := m.SyncSecrets(context.Background()); err != nil {
		t.Fatalf("SyncSecrets: %v", err)
	}
	var key secretKey
	copy(key.Prefix[:], "kl::toke")
	var val secretValue
	if err := objs.SecretMap.Lookup(&key, &val); err != nil {
		t.Errorf("secret_map: %v", err)
	}
	if hosts, err := readVirtualIPHosts(objs.VipHostIp); err != nil || len(hosts) != 1 {
		t.Errorf("vip_host_ip = %v, %v, want api.example.com", hosts, err)
	}
	if got, want := aclEntries(t, objs.SecretAcl), secretACL(m.lastSnapshot, m.bindings); len(want) == 0 || !maps.Equal(got, want) {
		t.Errorf("secret_acl has %d entries, want the %d the binding grants", len(got), len(want))
	}

	m.secretSource = errSource{errors.New("cache not started")}
	if err := m.SyncSecrets(context.Background()); err == nil || !strings.Contains(err.Error(), "cache not started") {
		t.Fatalf("SyncSecrets with a failing snapshot = %v, want its error", err)
	}
	if err := objs.SecretMap.Lookup(&key, &val); err != nil {
		t.Errorf("a failed snapshot pruned secret_map: %v", err)
	}
	if len(m.lastSnapshot) != 1 {
		t.Errorf("a failed snapshot replaced the last one: %d secrets", len(m.lastSnapshot))
	}
}
