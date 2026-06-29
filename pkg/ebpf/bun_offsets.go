package ebpf

import (
	"debug/elf"
	"os"
	"regexp"
)

// BunOffsets holds the file offset of SSL_write in a Bun single-executable
// plus the BoringSSL struct chain needed to walk SSL* → AES-GCM H subkey.
//
// Bun statically links BoringSSL with all internal symbols stripped from
// production and profile builds. The SSL_write file offset is pre-extracted
// from the official Bun profile release (same optimisation flags as
// production, symbol table retained) for each (version, arch) pair and
// stored here. Offset extraction is automated by tools/bun-offsets/.
//
// BoringSSL struct offsets reuse the same SSL→s3→aead_write_ctx→AES_KEY
// chain as the shared-library BoringSSL path (see boringssl_offsets.go).
// The layout has been stable across tracked Bun+BoringSSL revisions.
type BunOffsets struct {
	SSLWriteOffset uint64
	BoringSSL      BoringSSLOffsets
}

// bunOffsetTable maps "version/arch" to pre-extracted offsets.
// Populated and updated by tools/bun-offsets/apply-new-versions.sh.
// The version string matches what Bun embeds in the binary ("bun/X.Y.Z").
var bunOffsetTable = map[string]BunOffsets{
	// Extracted from bun-v1.3.14 profile builds (linux-x64-profile /
	// linux-aarch64-profile) on 2026-06-28.
	// SSL_write VA amd64: 0x3e62b50 → file offset 0x3c61b50 (63314768)
	// SSL_write VA arm64: 0x3976c40 → file offset 0x3766c40 (58092608)
	"1.3.14/amd64": {SSLWriteOffset: 63314768, BoringSSL: BoringSSLOffsets{SSLToS3: 48, S3ToAEAD: 272, AEADToAESKey: 288, SSLToWBIO: 32}},
	"1.3.14/arm64": {SSLWriteOffset: 58092608, BoringSSL: BoringSSLOffsets{SSLToS3: 48, S3ToAEAD: 272, AEADToAESKey: 288, SSLToWBIO: 32}},
}

var bunVersionRe = regexp.MustCompile(`bun/(\d+\.\d+\.\d+)`)

const (
	bunScanLimit = 64 * 1024 * 1024 // stop after 64 MiB (JS bundle follows ELF)
	bunChunkSize = 1 * 1024 * 1024  // 1 MiB read per iteration
	bunOverlap   = 32               // bytes carried over so strings can't straddle chunks
)

// DetectBun scans the binary at binPath for an embedded Bun version string
// ("bun/X.Y.Z"). Returns the pre-computed BunOffsets for the detected
// (version, arch) pair, the version string, and true on success.
//
// Only the first 64 MiB are scanned: Bun single-executables append the JS
// bundle after the ELF binary, and scanning the full file is unnecessary and
// slow. Scanning is done in 1 MiB chunks to avoid a single large heap
// allocation; the same file descriptor is reused for the ELF arch check.
func DetectBun(binPath string) (BunOffsets, string, bool) {
	f, err := os.Open(binPath)
	if err != nil {
		return BunOffsets{}, "", false
	}
	defer func() { _ = f.Close() }()

	version, ok := scanBunVersion(f)
	if !ok {
		return BunOffsets{}, "", false
	}
	arch := bunELFArchFromFile(f)

	key := version + "/" + arch
	if off, ok := bunOffsetTable[key]; ok {
		return off, version, true
	}
	return BunOffsets{}, version, false
}

// scanBunVersion reads f in bunChunkSize chunks (up to bunScanLimit bytes)
// looking for the embedded "bun/X.Y.Z" version string. An overlap of
// bunOverlap bytes is carried from each chunk to the next so that the pattern
// cannot be missed if it straddles a chunk boundary.
func scanBunVersion(f *os.File) (string, bool) {
	chunk := make([]byte, bunOverlap+bunChunkSize)
	var scanned int64
	overlapLen := 0

	for scanned < bunScanLimit {
		n, err := f.Read(chunk[overlapLen:])
		window := chunk[:overlapLen+n]
		scanned += int64(n)

		if m := bunVersionRe.FindSubmatch(window); m != nil {
			return string(m[1]), true
		}

		if n == 0 || err != nil {
			break
		}

		// Carry the last bunOverlap bytes into the next iteration so a version
		// string spanning the boundary is never split across two windows.
		if len(window) >= bunOverlap {
			copy(chunk[:bunOverlap], window[len(window)-bunOverlap:])
			overlapLen = bunOverlap
		} else {
			copy(chunk[:len(window)], window)
			overlapLen = len(window)
		}
	}
	return "", false
}

// bunELFArchFromFile returns "arm64" for AArch64 ELF binaries and "amd64"
// otherwise. It uses f (already open) via ReadAt so no seek is needed and no
// second open is required.
func bunELFArchFromFile(f *os.File) string {
	ef, err := elf.NewFile(f)
	if err != nil {
		return "amd64"
	}
	if ef.Machine == elf.EM_AARCH64 {
		return "arm64"
	}
	return "amd64"
}
