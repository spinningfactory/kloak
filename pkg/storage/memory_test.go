package storage

import (
	"context"
	"testing"
)

func TestMemory_StoreAndLookup(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	// Test Store and Lookup
	entry := Entry{Value: "secret-value", AllowedHosts: []string{"*"}}
	err := store.Store(ctx, "pod-1", "hash-1", entry)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Lookup the value
	gotEntry, found, err := store.Lookup(ctx, "hash-1")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !found {
		t.Error("Lookup failed to find stored hash")
	}
	if gotEntry.Value != "secret-value" {
		t.Errorf("Expected %s, got %s", "secret-value", gotEntry.Value)
	}
	if len(gotEntry.AllowedHosts) != 1 || gotEntry.AllowedHosts[0] != "*" {
		t.Errorf("Expected AllowedHosts to be ['*'], got %v", gotEntry.AllowedHosts)
	}

	// Lookup non-existent hash
	_, found, err = store.Lookup(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if found {
		t.Fatal("Expected to not find non-existent hash")
	}
}

func TestMemory_Delete(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	// Store values for two pods
	store.Store(ctx, "pod-1", "hash1", Entry{Value: "value1"})
	store.Store(ctx, "pod-1", "hash2", Entry{Value: "value2"})
	store.Store(ctx, "pod-2", "hash3", Entry{Value: "value3"})

	// Delete pod-1
	err := store.Delete(ctx, "pod-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify pod-1 hashes are gone
	_, found, _ := store.Lookup(ctx, "hash1")
	if found {
		t.Fatal("hash1 should be deleted")
	}
	_, found, _ = store.Lookup(ctx, "hash2")
	if found {
		t.Fatal("hash2 should be deleted")
	}

	// Verify pod-2 hash is still there
	entry, found, _ := store.Lookup(ctx, "hash3")
	if !found {
		t.Fatal("hash3 should still exist")
	}
	if entry.Value != "value3" {
		t.Fatalf("Expected 'value3', got '%s'", entry.Value)
	}
}

func TestMemory_List(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	store.Store(ctx, "pod-1", "hash1", Entry{Value: "value1"})
	store.Store(ctx, "pod-2", "hash2", Entry{Value: "value2"})

	all, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(all))
	}
	if all["hash1"].Value != "value1" || all["hash2"].Value != "value2" {
		t.Error("Stored values do not match")
	}
}

func TestMemory_ListByPod(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	store.Store(ctx, "pod-1", "hash-1", Entry{Value: "value1"})
	store.Store(ctx, "pod-1", "hash-2", Entry{Value: "value2"})
	store.Store(ctx, "pod-2", "hash-3", Entry{Value: "value3"})

	// ListByPod pod-1 should return 2 items
	items, err := store.ListByPod(ctx, "pod-1")
	if err != nil {
		t.Fatalf("ListByPod failed: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("Expected 2 items for pod-1, got %d", len(items))
	}

	if items["hash-1"].Value != "value1" {
		t.Errorf("Expected value1, got %s", items["hash-1"].Value)
	}
	if items["hash-2"].Value != "value2" {
		t.Errorf("Expected value2, got %s", items["hash-2"].Value)
	}

	// Non-existent pod returns empty map
	empty, _ := store.ListByPod(ctx, "nonexistent")
	if len(empty) != 0 {
		t.Fatal("Expected empty map for non-existent pod")
	}
}
