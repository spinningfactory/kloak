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
	Port         uint16   `json:"port"`
	Protocol     uint8    `json:"protocol"`
}

// Storage defines the interface for hash-to-value storage.
// Implementations can be in-memory, etcd, Redis, Vault, etc.
type Storage interface {
	// Store saves a hash→Entry mapping. The ownerID identifies what owns this shadow
	// (e.g., a secret namespace/name). If the hash already exists, it updates the entry.
	Store(ctx context.Context, ownerID, hash string, entry Entry) error

	// Lookup retrieves the original entry for a hash.
	// Returns the entry, whether it was found, and any error.
	Lookup(ctx context.Context, hash string) (Entry, bool, error)

	// Delete removes all mappings for an owner.
	Delete(ctx context.Context, ownerID string) error

	// List returns all hash→Entry mappings.
	// Used for syncing to eBPF maps.
	List(ctx context.Context) (map[string]Entry, error)

	// GetOwnerID returns the ownerID associated with a hash, if any.
	GetOwnerID(ctx context.Context, hash string) (string, bool, error)
}
