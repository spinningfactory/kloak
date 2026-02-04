// Package storage provides an interface for hash-to-value storage
// with pluggable implementations (in-memory, etcd, etc.)
package storage

import (
	"context"
)

// Storage defines the interface for hash-to-value storage.
// Implementations can be in-memory, etcd, Redis, Vault, etc.
type Storage interface {
	// Store saves a hash→value mapping for a pod.
	// If the hash already exists, it updates the value.
	Store(ctx context.Context, podID, hash, value string) error

	// Lookup retrieves the original value for a hash.
	// Returns the value, whether it was found, and any error.
	Lookup(ctx context.Context, hash string) (value string, found bool, err error)

	// Delete removes all mappings for a pod.
	Delete(ctx context.Context, podID string) error

	// List returns all hash→value mappings.
	// Used for syncing to XDS/ext_proc.
	List(ctx context.Context) (map[string]string, error)

	// ListByPod returns all hash→value mappings for a specific pod.
	ListByPod(ctx context.Context, podID string) (map[string]string, error)
}
