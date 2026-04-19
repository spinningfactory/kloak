//go:build linux

package ebpf

import (
	"context"
	"strings"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// createTestSecretMap creates a BPF hash map matching the secret_map spec.
func createTestSecretMap(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type:       ciliumebpf.Hash,
		KeySize:    8,   // SECRET_KEY_LEN
		ValueSize:  272, // sizeof(secret_value) with padding (including IP filtering fields)
		MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// createTestWatchedHostsMap creates a BPF hash map matching the watched_hosts spec.
func createTestWatchedHostsMap(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type:       ciliumebpf.Hash,
		KeySize:    32, // MAX_HOST_LEN
		ValueSize:  1,  // __u8
		MaxEntries: 256,
	})
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
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
func enabledSecret(name, ns string, data map[string][]byte, labels map[string]string) *corev1.Secret {
	l := map[string]string{"getkloak.io/enabled": "true"}
	for k, v := range labels {
		l[k] = v
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    l,
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
			map[string][]byte{"api-key": []byte("my-real-secret-value!")}, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kloak:abcd1234-5678-9abc")}),
	)

	if err := syncSecrets(context.Background(), m, nil, reader, testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	// Verify the key was stored (first 8 bytes of shadow prefix)
	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
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
	// Shadow value "kloak:" is 6 bytes, below 8-byte minimum
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("short")}, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kloak:")}),
	)

	if err := syncSecrets(context.Background(), m, nil, reader, testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	// Map should be empty — secret was too short
	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
	var val secretValue
	if err := m.Lookup(&key, &val); err == nil {
		t.Error("short secret should not be stored in BPF map")
	}
}

func TestSyncSecrets_Truncation(t *testing.T) {
	m := createTestSecretMap(t)
	longValue := strings.Repeat("A", 200)
	longShadow := "kloak:abcd1234-5678-9abc-def0-123456789abc" + strings.Repeat(" ", 158)
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte(longValue)}, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte(longShadow)}),
	)

	if err := syncSecrets(context.Background(), m, nil, reader, testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
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
			map[string]string{"getkloak.io/hosts": "api.stripe.com"}),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kloak:abcd1234-5678-9abc")}),
	)

	if err := syncSecrets(context.Background(), m, nil, reader, testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
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
			map[string]string{"getkloak.io/hosts": "*"}),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kloak:abcd1234-5678-9abc")}),
	)

	if err := syncSecrets(context.Background(), m, nil, reader, testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
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
			map[string][]byte{"api-key": []byte("my-real-secret-value!")}, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kloak:abcd1234-5678-9abc")}),
	)
	if err := syncSecrets(context.Background(), m, nil, reader1, testLog()); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}

	// Verify it exists
	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found after first sync: %v", err)
	}

	// Remove the enabled secret (simulate deletion) and sync again with empty client
	reader2 := newFakeClient()
	if err := syncSecrets(context.Background(), m, nil, reader2, testLog()); err != nil {
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
			map[string][]byte{"api-key": []byte("old-secret-value-here")}, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kloak:abcd1234-5678-9abc")}),
	)
	if err := syncSecrets(context.Background(), m, nil, reader1, testLog()); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}

	// Update value (same shadow, different real value)
	reader2 := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("new-secret-value-here")}, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kloak:abcd1234-5678-9abc")}),
	)
	if err := syncSecrets(context.Background(), m, nil, reader2, testLog()); err != nil {
		t.Fatalf("second sync failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
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
	shadow := "kloak:abcd1234-5678-9abc-def0-123456789abc"
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte(shadow)}, nil),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte(shadow)}),
	)

	if err := syncSecrets(context.Background(), m, nil, reader, testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
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

func TestSyncSecrets_WatchedHostsSync(t *testing.T) {
	m := createTestSecretMap(t)
	wh := createTestWatchedHostsMap(t)
	reader := newFakeClient(
		enabledSecret("secret1", "default",
			map[string][]byte{"api-key": []byte("my-real-secret-value!")},
			map[string]string{"getkloak.io/hosts": "api.stripe.com"}),
		shadowSecret("secret1-kloak", "default", "secret1",
			map[string][]byte{"api-key": []byte("kloak:abcd1234-5678-9abc")}),
		enabledSecret("secret2", "default",
			map[string][]byte{"api-key": []byte("another-secret-value!")},
			map[string]string{"getkloak.io/hosts": "api.github.com"}),
		shadowSecret("secret2-kloak", "default", "secret2",
			map[string][]byte{"api-key": []byte("kloak:efgh5678-1234-5678")}),
	)

	if err := syncSecrets(context.Background(), m, wh, reader, testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	// Verify both hosts are in watched_hosts map
	var key1 watchedHostKey
	copy(key1.Host[:], "api.stripe.com")
	var val uint8
	if err := wh.Lookup(&key1, &val); err != nil {
		t.Fatalf("api.stripe.com not found in watched_hosts: %v", err)
	}

	var key2 watchedHostKey
	copy(key2.Host[:], "api.github.com")
	if err := wh.Lookup(&key2, &val); err != nil {
		t.Fatalf("api.github.com not found in watched_hosts: %v", err)
	}
}

func TestSyncSecrets_WatchedHostsPruning(t *testing.T) {
	m := createTestSecretMap(t)
	wh := createTestWatchedHostsMap(t)

	// First sync: add a secret with host
	reader1 := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("my-real-secret-value!")},
			map[string]string{"getkloak.io/hosts": "api.stripe.com"}),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kloak:abcd1234-5678-9abc")}),
	)
	if err := syncSecrets(context.Background(), m, wh, reader1, testLog()); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}

	// Verify host exists
	var key watchedHostKey
	copy(key.Host[:], "api.stripe.com")
	var val uint8
	if err := wh.Lookup(&key, &val); err != nil {
		t.Fatalf("host not found after first sync: %v", err)
	}

	// Remove secret and sync again
	reader2 := newFakeClient()
	if err := syncSecrets(context.Background(), m, wh, reader2, testLog()); err != nil {
		t.Fatalf("second sync failed: %v", err)
	}

	// Host should be pruned
	if err := wh.Lookup(&key, &val); err == nil {
		t.Error("stale host should have been pruned from watched_hosts map")
	}
}

func TestSyncSecrets_IPFilter(t *testing.T) {
	m := createTestSecretMap(t)
	reader := newFakeClient(
		enabledSecret("my-secret", "default",
			map[string][]byte{"api-key": []byte("my-real-secret-value!")},
			map[string]string{"getkloak.io/hosts": "192.168.1.1"}),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kloak:abcd1234-5678-9abc")}),
	)

	if err := syncSecrets(context.Background(), m, nil, reader, testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
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
			map[string]string{"getkloak.io/hosts": "2001:db8::1"}),
		shadowSecret("my-secret-kloak", "default", "my-secret",
			map[string][]byte{"api-key": []byte("kloak:abcd1234-5678-9abc")}),
	)

	if err := syncSecrets(context.Background(), m, nil, reader, testLog()); err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
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
	if err := syncSecrets(context.Background(), m, nil, nil, testLog()); err != nil {
		t.Fatalf("syncSecrets with nil reader should not error: %v", err)
	}
}
