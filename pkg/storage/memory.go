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
	// ownerToHashes maps ownerID → set of hashes
	ownerToHashes map[string]map[string]struct{}
	// hashToOwner maps hash → ownerID (for reverse lookup)
	hashToOwner map[string]string
}

// NewMemory creates a new in-memory storage.
func NewMemory() *Memory {
	return &Memory{
		hashToEntry:   make(map[string]Entry),
		ownerToHashes: make(map[string]map[string]struct{}),
		hashToOwner:   make(map[string]string),
	}
}

// Store saves a hash→Entry mapping for an owner.
func (m *Memory) Store(ctx context.Context, ownerID, hash string, entry Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store hash → Entry
	m.hashToEntry[hash] = entry

	// Track hash → owner relationship
	m.hashToOwner[hash] = ownerID

	// Track owner → hashes relationship
	if m.ownerToHashes[ownerID] == nil {
		m.ownerToHashes[ownerID] = make(map[string]struct{})
	}
	m.ownerToHashes[ownerID][hash] = struct{}{}

	return nil
}

// Lookup retrieves the original Entry for a hash.
func (m *Memory) Lookup(ctx context.Context, hash string) (Entry, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, found := m.hashToEntry[hash]
	return entry, found, nil
}

// Delete removes all mappings for an owner.
func (m *Memory) Delete(ctx context.Context, ownerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get all hashes for this owner
	hashes, exists := m.ownerToHashes[ownerID]
	if !exists {
		return nil
	}

	// Remove each hash
	for hash := range hashes {
		delete(m.hashToEntry, hash)
		delete(m.hashToOwner, hash)
	}

	// Remove owner tracking
	delete(m.ownerToHashes, ownerID)

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

// GetOwnerID returns the ownerID associated with a hash.
func (m *Memory) GetOwnerID(ctx context.Context, hash string) (ownerID string, found bool, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ownerID, found = m.hashToOwner[hash]
	return ownerID, found, nil
}

// Compile-time check that Memory implements Storage
var _ Storage = (*Memory)(nil)
