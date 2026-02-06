// Package storage provides an interface for hash-to-value storage
// with pluggable implementations (in-memory, etcd, etc.)
package storage

import (
	"context"
)

// Entry represents a stored value with metadata.
type Entry struct {
	Value        string   `json:"value"`
	AllowedHosts []string `json:"allowed_hosts"`
}

// Storage defines the interface for hash-to-value storage.
// Implementations can be in-memory, etcd, Redis, Vault, etc.
type Storage interface {
	// Store saves a hash→Entry mapping for a pod.
	// If the hash already exists, it updates the entry.
	Store(ctx context.Context, podID, hash string, entry Entry) error

	// Lookup retrieves the original entry for a hash.
	// Returns the entry, whether it was found, and any error.
	Lookup(ctx context.Context, hash string) (Entry, bool, error)

	// Delete removes all mappings for a pod.
	Delete(ctx context.Context, podID string) error

	// List returns all hash→Entry mappings.
	// Used for syncing to XDS/ext_proc.
	List(ctx context.Context) (map[string]Entry, error)

	// ListByPod returns all hash→Entry mappings for a specific pod.
	ListByPod(ctx context.Context, podID string) (map[string]Entry, error)
}
