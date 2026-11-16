//go:build linux

package ebpf

// secretChunkLen is SECRET_CHUNK_LEN in bpf/tls_uprobe.c: the bytes of a
// placeholder one secret_chunks entry holds.
const secretChunkLen = 256

// secretChunkKey matches C struct secret_chunk_key.
type secretChunkKey struct {
	Key secretKey // the secret_map key
	Gen uint32    // secretValue.Gen of the entry
	Idx uint32    // chunk index: bytes [Idx*secretChunkLen, (Idx+1)*secretChunkLen)
}

// secretChunk matches C struct secret_chunk.
type secretChunk struct {
	Shadow [secretChunkLen]byte // the placeholder as on the wire
	Delta  [secretChunkLen]byte // Shadow XOR the real value as on the wire
}
