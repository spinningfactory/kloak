package storage

import (
	"context"
	"sync"
)

// Memory is an in-memory implementation of Storage.
// Thread-safe for concurrent access.
type Memory struct {
	mu sync.RWMutex
	// hashToValue maps hash → original value
	hashToValue map[string]string
	// podToHashes maps podID → set of hashes
	podToHashes map[string]map[string]struct{}
	// hashToPod maps hash → podID (for reverse lookup)
	hashToPod map[string]string
}

// NewMemory creates a new in-memory storage.
func NewMemory() *Memory {
	return &Memory{
		hashToValue: make(map[string]string),
		podToHashes: make(map[string]map[string]struct{}),
		hashToPod:   make(map[string]string),
	}
}

// Store saves a hash→value mapping for a pod.
func (m *Memory) Store(ctx context.Context, podID, hash, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store hash → value
	m.hashToValue[hash] = value

	// Track hash → pod relationship
	m.hashToPod[hash] = podID

	// Track pod → hashes relationship
	if m.podToHashes[podID] == nil {
		m.podToHashes[podID] = make(map[string]struct{})
	}
	m.podToHashes[podID][hash] = struct{}{}

	return nil
}

// Lookup retrieves the original value for a hash.
func (m *Memory) Lookup(ctx context.Context, hash string) (string, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	value, found := m.hashToValue[hash]
	return value, found, nil
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
		delete(m.hashToValue, hash)
		delete(m.hashToPod, hash)
	}

	// Remove pod tracking
	delete(m.podToHashes, podID)

	return nil
}

// List returns all hash→value mappings.
func (m *Memory) List(ctx context.Context) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]string, len(m.hashToValue))
	for k, v := range m.hashToValue {
		result[k] = v
	}
	return result, nil
}

// ListByPod returns all hash→value mappings for a specific pod.
func (m *Memory) ListByPod(ctx context.Context, podID string) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hashes, exists := m.podToHashes[podID]
	if !exists {
		return map[string]string{}, nil
	}

	result := make(map[string]string, len(hashes))
	for hash := range hashes {
		if value, ok := m.hashToValue[hash]; ok {
			result[hash] = value
		}
	}
	return result, nil
}

// Compile-time check that Memory implements Storage
var _ Storage = (*Memory)(nil)
