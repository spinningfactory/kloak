package storage

import (
	"context"
	"sync"
)

// Memory is an in-memory implementation of Storage.
// Thread-safe for concurrent access.
type Memory struct {
	mu sync.RWMutex
	// hashToEntry maps hash → Entry
	hashToEntry map[string]Entry
	// podToHashes maps podID → set of hashes
	podToHashes map[string]map[string]struct{}
	// hashToPod maps hash → podID (for reverse lookup)
	hashToPod map[string]string
	// prefixToPod maps first-8-bytes-of-hash → podID (for eBPF matched_key lookup)
	prefixToPod map[string]string
}

// NewMemory creates a new in-memory storage.
func NewMemory() *Memory {
	return &Memory{
		hashToEntry: make(map[string]Entry),
		podToHashes: make(map[string]map[string]struct{}),
		hashToPod:   make(map[string]string),
		prefixToPod: make(map[string]string),
	}
}

// Store saves a hash→Entry mapping for a pod.
func (m *Memory) Store(ctx context.Context, podID, hash string, entry Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store hash → Entry
	m.hashToEntry[hash] = entry

	// Track hash → pod relationship
	m.hashToPod[hash] = podID

	// Track pod → hashes relationship
	if m.podToHashes[podID] == nil {
		m.podToHashes[podID] = make(map[string]struct{})
	}
	m.podToHashes[podID][hash] = struct{}{}

	// Maintain prefix index (first 8 bytes of hash → podID)
	if len(hash) >= 8 {
		m.prefixToPod[hash[:8]] = podID
	}

	return nil
}

// Lookup retrieves the original Entry for a hash.
func (m *Memory) Lookup(ctx context.Context, hash string) (Entry, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, found := m.hashToEntry[hash]
	return entry, found, nil
}

// Delete removes all mappings for a pod.
func (m *Memory) Delete(ctx context.Context, podID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get all hashes for this pod
	hashes, exists := m.podToHashes[podID]
	if !exists {
		return nil
	}

	// Remove each hash
	for hash := range hashes {
		delete(m.hashToEntry, hash)
		delete(m.hashToPod, hash)
		if len(hash) >= 8 {
			delete(m.prefixToPod, hash[:8])
		}
	}

	// Remove pod tracking
	delete(m.podToHashes, podID)

	return nil
}

// List returns all hash→Entry mappings.
func (m *Memory) List(ctx context.Context) (map[string]Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]Entry, len(m.hashToEntry))
	for k, v := range m.hashToEntry {
		result[k] = v
	}
	return result, nil
}

// LookupByPrefix finds the podID (namespace/secretName) that owns a
// shadow hash whose first 8 bytes match the given prefix.
func (m *Memory) LookupByPrefix(ctx context.Context, prefix string) (string, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	podID, found := m.prefixToPod[prefix]
	return podID, found, nil
}

// Compile-time check that Memory implements Storage
var _ Storage = (*Memory)(nil)
