//go:build linux

package ebpf

import (
	"context"
	"strings"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/spinningfactory/kloak/pkg/storage"
)

func init() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
}

// createTestSecretMap creates a BPF hash map matching the secret_map spec.
func createTestSecretMap(t *testing.T) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type:       ciliumebpf.Hash,
		KeySize:    8,   // SECRET_KEY_LEN
		ValueSize:  216, // sizeof(secret_value) with padding
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

func testLog() logr.Logger {
	return ctrl.Log.WithName("test")
}

func TestSyncSecrets_BasicSync(t *testing.T) {
	m := createTestSecretMap(t)
	store := storage.NewMemory()
	_ = store.Store(context.Background(), "pod1", "kloak:abcd1234-5678-9abc", storage.Entry{
		Value: "my-real-secret-value!",
	})

	if err := syncSecrets(m, nil, store, testLog()); err != nil {
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
	store := storage.NewMemory()
	// Secret value is 5 bytes — shadow prefix will be 5 bytes, below 8-byte minimum
	_ = store.Store(context.Background(), "pod1", "kloak:ab", storage.Entry{
		Value: "short",
	})

	if err := syncSecrets(m, nil, store, testLog()); err != nil {
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
	store := storage.NewMemory()
	longValue := strings.Repeat("A", 200)
	_ = store.Store(context.Background(), "pod1", "kloak:abcd1234-5678-9abc-def0-123456789abc"+strings.Repeat(" ", 158), storage.Entry{
		Value: longValue,
	})

	if err := syncSecrets(m, nil, store, testLog()); err != nil {
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
	store := storage.NewMemory()
	_ = store.Store(context.Background(), "pod1", "kloak:abcd1234-5678-9abc", storage.Entry{
		Value:        "my-real-secret-value!",
		AllowedHosts: []string{"api.stripe.com"},
	})

	if err := syncSecrets(m, nil, store, testLog()); err != nil {
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
	store := storage.NewMemory()
	_ = store.Store(context.Background(), "pod1", "kloak:abcd1234-5678-9abc", storage.Entry{
		Value:        "my-real-secret-value!",
		AllowedHosts: []string{"*"},
	})

	if err := syncSecrets(m, nil, store, testLog()); err != nil {
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
	store := storage.NewMemory()

	// First sync: add a secret
	_ = store.Store(context.Background(), "pod1", "kloak:abcd1234-5678-9abc", storage.Entry{
		Value: "my-real-secret-value!",
	})
	if err := syncSecrets(m, nil, store, testLog()); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}

	// Verify it exists
	var key secretKey
	copy(key.Prefix[:], []byte("kloak:ab"))
	var val secretValue
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("secret not found after first sync: %v", err)
	}

	// Remove from storage and sync again
	_ = store.Delete(context.Background(), "pod1")
	if err := syncSecrets(m, nil, store, testLog()); err != nil {
		t.Fatalf("second sync failed: %v", err)
	}

	// Should be pruned
	if err := m.Lookup(&key, &val); err == nil {
		t.Error("stale entry should have been pruned from BPF map")
	}
}

func TestSyncSecrets_Update(t *testing.T) {
	m := createTestSecretMap(t)
	store := storage.NewMemory()

	// Initial value
	_ = store.Store(context.Background(), "pod1", "kloak:abcd1234-5678-9abc", storage.Entry{
		Value: "old-secret-value-here",
	})
	if err := syncSecrets(m, nil, store, testLog()); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}

	// Update value (same hash, different value)
	_ = store.Store(context.Background(), "pod1", "kloak:abcd1234-5678-9abc", storage.Entry{
		Value: "new-secret-value-here",
	})
	if err := syncSecrets(m, nil, store, testLog()); err != nil {
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
	store := storage.NewMemory()
	hash := "kloak:abcd1234-5678-9abc-def0-123456789abc"
	_ = store.Store(context.Background(), "pod1", hash, storage.Entry{
		Value: "kloak:abcd1234-5678-9abc-def0-123456789abc",
	})

	if err := syncSecrets(m, nil, store, testLog()); err != nil {
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
	if gotPrefix != hash[:42] {
		t.Errorf("expected prefix %q, got %q", hash[:42], gotPrefix)
	}
}

func TestSyncSecrets_WatchedHostsSync(t *testing.T) {
	m := createTestSecretMap(t)
	wh := createTestWatchedHostsMap(t)
	store := storage.NewMemory()

	_ = store.Store(context.Background(), "pod1", "kloak:abcd1234-5678-9abc", storage.Entry{
		Value:        "my-real-secret-value!",
		AllowedHosts: []string{"api.stripe.com"},
	})
	_ = store.Store(context.Background(), "pod2", "kloak:efgh5678-1234-5678", storage.Entry{
		Value:        "another-secret-value!",
		AllowedHosts: []string{"api.github.com"},
	})

	if err := syncSecrets(m, wh, store, testLog()); err != nil {
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
	store := storage.NewMemory()

	// First sync: add a secret with host
	_ = store.Store(context.Background(), "pod1", "kloak:abcd1234-5678-9abc", storage.Entry{
		Value:        "my-real-secret-value!",
		AllowedHosts: []string{"api.stripe.com"},
	})
	if err := syncSecrets(m, wh, store, testLog()); err != nil {
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
	_ = store.Delete(context.Background(), "pod1")
	if err := syncSecrets(m, wh, store, testLog()); err != nil {
		t.Fatalf("second sync failed: %v", err)
	}

	// Host should be pruned
	if err := wh.Lookup(&key, &val); err == nil {
		t.Error("stale host should have been pruned from watched_hosts map")
	}
}
