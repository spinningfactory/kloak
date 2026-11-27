package ebpf

import (
	"fmt"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// The secret store's byte budget (SecretStoreConfig.Bytes).
//
// secret_chunks is a preallocated hash map: the kernel reserves every entry
// when the map is created, so the budget is memory the node gives the store
// whether secrets fill it or not, charged to the controller's memory cgroup
// (Helm: controller.resources.limits.memory). An entry is a 256-byte chunk
// of a placeholder and its 256-byte delta (secretChunk), keyed by
// secretChunkKey, and every secret has two entries per chunk of its value:
// its placeholder's, and its HPACK-Huffman form's (somewhat shorter).
//
// The default, 16 MiB (about 27,000 chunks), holds:
//   - one chunk for every entry secret_map can hold (4096), twice over (a
//     changed secret's previous generation stays for secretStoreGrace),
//     which is all the store needs while the data plane takes secrets of at
//     most secrets.DataPlaneMaxLen (128) bytes: about 4.8 MiB;
//   - and, once it takes longer ones, about 19,000 chunks more: some 40
//     secrets of the default maximum length (64 KiB, about 450 chunks for
//     both forms), or 20 of them changing at once.
//
// Raise it for more or longer secrets; a secret that does not fit is left
// out of the data plane (its placeholder goes out unchanged), logged, and
// counted in kloak_secret_store_refused_entries{reason="full"}.
const (
	DefaultSecretStoreBytes = 16 << 20
	MinSecretStoreBytes     = 1 << 20
	MaxSecretStoreBytes     = 1 << 30
)

// secretChunkLen is SECRET_CHUNK_LEN in bpf/tls_uprobe.c: the bytes of a
// placeholder one secret_chunks entry holds.
const secretChunkLen = 256

// secretChunkEntryBytes is about what one secret_chunks entry takes in the
// kernel: the 48-byte element header (struct htab_elem on a 64-bit kernel),
// the 16-byte key and the value, each rounded up to 8 bytes, and up to two
// 16-byte bucket heads (the map has a power of two of buckets, at least one
// per entry).
const secretChunkEntryBytes = 48 + 16 + 2*secretChunkLen + 2*16

// SecretStoreConfig sizes the secret store and bounds what is synced into
// it. The zero value is the defaults.
type SecretStoreConfig struct {
	// Bytes is the kernel memory secret_chunks reserves on the node (see
	// DefaultSecretStoreBytes); 0: the default. A controller started with
	// another budget than the one that loaded the pinned data plane loads it
	// again (the pinned map is not adopted).
	Bytes int64
	// MaxSecretLen is the cluster's policy maximum for a secret value's
	// length (secrets.EffectiveMaxLen clamps it to what the data plane
	// takes); 0: secrets.DefaultMaxLen. A longer value is left out of the
	// data plane.
	MaxSecretLen int
}

// Validate checks the budget and the policy maximum.
func (c SecretStoreConfig) Validate() error {
	if b := c.bytes(); b < MinSecretStoreBytes || b > MaxSecretStoreBytes {
		return fmt.Errorf("secret store budget %d bytes is out of range [%d, %d]", b, MinSecretStoreBytes, MaxSecretStoreBytes)
	}
	return secrets.ValidateMaxLen(c.policyMaxLen())
}

func (c SecretStoreConfig) bytes() int64 {
	if c.Bytes == 0 {
		return DefaultSecretStoreBytes
	}
	return c.Bytes
}

func (c SecretStoreConfig) policyMaxLen() int {
	if c.MaxSecretLen == 0 {
		return secrets.DefaultMaxLen
	}
	return c.MaxSecretLen
}

// maxLen is the longest secret value synced into the data plane.
func (c SecretStoreConfig) maxLen() int {
	return secrets.EffectiveMaxLen(c.policyMaxLen())
}

// chunkEntries is secret_chunks' max_entries for the budget (Validate
// bounds it).
func (c SecretStoreConfig) chunkEntries() uint32 {
	return uint32(c.bytes() / secretChunkEntryBytes)
}
