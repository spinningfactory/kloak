package storage

import (
	"context"
	"testing"
)

func TestMemory_StoreAndLookup(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	// Store a value
	err := store.Store(ctx, "pod-1", "abc123", "secret-value")
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Lookup the value
	value, found, err := store.Lookup(ctx, "abc123")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !found {
		t.Fatal("Expected to find hash")
	}
	if value != "secret-value" {
		t.Fatalf("Expected 'secret-value', got '%s'", value)
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
	store.Store(ctx, "pod-1", "hash1", "value1")
	store.Store(ctx, "pod-1", "hash2", "value2")
	store.Store(ctx, "pod-2", "hash3", "value3")

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
	value, found, _ := store.Lookup(ctx, "hash3")
	if !found {
		t.Fatal("hash3 should still exist")
	}
	if value != "value3" {
		t.Fatalf("Expected 'value3', got '%s'", value)
	}
}

func TestMemory_List(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	store.Store(ctx, "pod-1", "hash1", "value1")
	store.Store(ctx, "pod-2", "hash2", "value2")

	all, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(all))
	}
	if all["hash1"] != "value1" || all["hash2"] != "value2" {
		t.Fatal("Unexpected values in list")
	}
}

func TestMemory_ListByPod(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	store.Store(ctx, "pod-1", "hash1", "value1")
	store.Store(ctx, "pod-1", "hash2", "value2")
	store.Store(ctx, "pod-2", "hash3", "value3")

	pod1Hashes, err := store.ListByPod(ctx, "pod-1")
	if err != nil {
		t.Fatalf("ListByPod failed: %v", err)
	}
	if len(pod1Hashes) != 2 {
		t.Fatalf("Expected 2 entries for pod-1, got %d", len(pod1Hashes))
	}

	// Non-existent pod returns empty map
	empty, _ := store.ListByPod(ctx, "nonexistent")
	if len(empty) != 0 {
		t.Fatal("Expected empty map for non-existent pod")
	}
}
