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

// DetectBun scans the binary at binPath for an embedded Bun version string
// ("bun/X.Y.Z"). Returns the pre-computed BunOffsets for the detected
// (version, arch) pair, the version string, and true on success.
//
// Only the first 64 MiB are scanned: Bun single-executables append the JS
// bundle after the ELF binary, and scanning the full file is unnecessary and
// slow.
func DetectBun(binPath string) (BunOffsets, string, bool) {
	f, err := os.Open(binPath)
	if err != nil {
		return BunOffsets{}, "", false
	}
	defer f.Close()

	// Scan only the first 64 MiB to cover the ELF runtime without reading
	// the (potentially large) bundled JS payload that follows.
	buf := make([]byte, 64*1024*1024)
	n, _ := f.Read(buf)
	buf = buf[:n]

	m := bunVersionRe.FindSubmatch(buf)
	if m == nil {
		return BunOffsets{}, "", false
	}
	version := string(m[1])
	arch := bunELFArch(binPath)

	key := version + "/" + arch
	if off, ok := bunOffsetTable[key]; ok {
		return off, version, true
	}
	return BunOffsets{}, version, false
}

// bunELFArch returns "arm64" for AArch64 ELF binaries and "amd64" otherwise.
func bunELFArch(binPath string) string {
	f, err := elf.Open(binPath)
	if err != nil {
		return "amd64"
	}
	defer f.Close()
	if f.Machine == elf.EM_AARCH64 {
		return "arm64"
	}
	return "amd64"
}
