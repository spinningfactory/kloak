package ebpf

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"strings"
)

// TLSOffsets contains struct offsets for extracting TLS key material from an
// SSL* object at runtime. The offsets form a 3-level pointer chain:
//
//	SSL* + EncWriteCtx → EVP_CIPHER_CTX* + CipherData → data* + GHashH → H (16 bytes)
//
// Plus a direct offset for the cipher suite ID:
//
//	SSL* + CipherSuiteID → uint16 cipher suite
//
// These are version-specific and must match the OpenSSL build in the container.
type TLSOffsets struct {
	SSLToWRL       uint32 // SSL* + off → OSSL_RECORD_LAYER* (pointer deref)
	WRLToEncCtx    uint32 // wrl* + off → EVP_CIPHER_CTX* (pointer deref)
	EncCtxToAlgctx uint32 // enc_ctx* + off → algctx/PROV_GCM_CTX* (pointer deref)
	AlgctxToH      uint32 // algctx* + off → H (16 bytes, direct read)
}

// opensslOffsetTable maps OpenSSL major.minor version strings to their TLS
// struct offsets. Determined by compiling OpenSSL at each version and
// inspecting struct layouts with pahole/gdb/offsetof.
//
// To add a new version:
//  1. Build OpenSSL with debug symbols
//  2. Use pahole or gdb to find:
//     - offsetof(SSL, enc_write_ctx)
//     - offsetof(EVP_CIPHER_CTX, cipher_data)
//     - offsetof(EVP_AES_GCM_CTX, gcm) + offsetof(GCM128_CONTEXT, Htable)
//     - offsetof(SSL, s3) + offsetof(SSL3_STATE, tmp) + offsetof(tmp, new_cipher) + offsetof(SSL_CIPHER, id)
//  3. Add a row to this table
//
// TODO: These offsets are placeholders. Must be verified per version/arch.
var opensslOffsetTable = map[string]TLSOffsets{
	// OpenSSL 3.5.x (Debian Trixie) — aarch64
	// Determined empirically via offsetof() with internal headers.
	// Chain: SSL_CONNECTION.rlayer.wrl → enc_ctx → algctx → gcm.H
	// GCM_IV_MAX_SIZE=128 in OpenSSL 3.5 shifts gcm field by +112 vs our initial calculation.
	// Correct: PROV_GCM_CTX.gcm at 248 (not 136), GCM128_CONTEXT.H at +80 → 248+80=328
	"3.5": {SSLToWRL: 3208, WRLToEncCtx: 4128, EncCtxToAlgctx: 176, AlgctxToH: 328},

	// TODO: Add offsets for other versions/architectures.
	// OpenSSL 3.0-3.4 had enc_write_ctx directly on SSL_CONNECTION (fewer hops).
	// x86_64 will have different offsets due to struct packing differences.
}

// DetectOpenSSLVersion reads an OpenSSL/libssl shared library from a
// container's filesystem and determines its version. Returns the version
// string (e.g., "3.2.1") and the corresponding struct offsets.
//
// The library is accessed via /proc/<pid>/root/<libPath> to reach into
// the container's overlay filesystem.
func DetectOpenSSLVersion(pid int, libPath string) (version string, offsets TLSOffsets, err error) {
	hostPath := fmt.Sprintf("/proc/%d/root%s", pid, libPath)

	f, err := elf.Open(hostPath)
	if err != nil {
		return "", TLSOffsets{}, fmt.Errorf("opening ELF %s: %w", hostPath, err)
	}
	defer func() { _ = f.Close() }()

	version, err = readOpenSSLVersion(f)
	if err != nil {
		return "", TLSOffsets{}, fmt.Errorf("reading OpenSSL version from %s: %w", hostPath, err)
	}

	// Extract major.minor for offset lookup
	majorMinor := extractMajorMinor(version)
	offsets, ok := opensslOffsetTable[majorMinor]
	if !ok {
		return version, TLSOffsets{}, fmt.Errorf("unsupported OpenSSL version %s (major.minor=%s)", version, majorMinor)
	}

	if offsets.SSLToWRL == 0 {
		return version, offsets, fmt.Errorf("OpenSSL %s offsets not yet calibrated (SSLToWRL=0)", version)
	}

	return version, offsets, nil
}

// readOpenSSLVersion attempts to find the OpenSSL version string in the
// library's .rodata section. Looks for patterns like "OpenSSL 3.2.1 ".
func readOpenSSLVersion(f *elf.File) (string, error) {
	// Try .rodata first, then .data
	for _, name := range []string{".rodata", ".data"} {
		sec := f.Section(name)
		if sec == nil {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		if v := findVersionInData(data); v != "" {
			return v, nil
		}
	}

	// Fallback: check for OpenSSL_version_num symbol
	syms, err := f.DynamicSymbols()
	if err == nil {
		for _, sym := range syms {
			if sym.Name == "OpenSSL_version_num" && sym.Value != 0 {
				return readVersionFromSymbol(f, &sym)
			}
		}
	}

	return "", fmt.Errorf("could not determine OpenSSL version")
}

// findVersionInData scans a byte slice for "OpenSSL X.Y.Z" patterns.
func findVersionInData(data []byte) string {
	prefix := []byte("OpenSSL ")
	for i := 0; i+len(prefix)+5 < len(data); i++ {
		if data[i] != 'O' {
			continue
		}
		if !startsWith(data[i:], prefix) {
			continue
		}
		// Extract version string after "OpenSSL "
		start := i + len(prefix)
		end := start
		for end < len(data) && end-start < 20 && data[end] != ' ' && data[end] != 0 && data[end] != '\n' {
			end++
		}
		version := string(data[start:end])
		// Validate: must look like X.Y.Z
		if len(version) >= 3 && version[0] >= '0' && version[0] <= '9' {
			return version
		}
	}
	return ""
}

func startsWith(data, prefix []byte) bool {
	if len(data) < len(prefix) {
		return false
	}
	for i := range prefix {
		if data[i] != prefix[i] {
			return false
		}
	}
	return true
}

// readVersionFromSymbol reads the version number from the OpenSSL_version_num
// symbol value. The version number is encoded as 0xMNN00PP0 where M=major,
// NN=minor, PP=patch (OpenSSL 3.x encoding).
func readVersionFromSymbol(f *elf.File, sym *elf.Symbol) (string, error) {
	// For OpenSSL 3.x, the version_num function returns a value, not a constant.
	// We can try to read from the .data section at the symbol's address.
	for _, sec := range f.Sections {
		if sec.Addr > sym.Value || sym.Value >= sec.Addr+sec.Size {
			continue
		}
		offset := sym.Value - sec.Addr
		data, err := sec.Data()
		if err != nil || offset+4 > uint64(len(data)) {
			continue
		}
		var num uint32
		if f.ByteOrder == binary.LittleEndian {
			num = binary.LittleEndian.Uint32(data[offset:])
		} else {
			num = binary.BigEndian.Uint32(data[offset:])
		}
		if num > 0 {
			major := (num >> 28) & 0xF
			minor := (num >> 20) & 0xFF
			patch := (num >> 4) & 0xFF
			return fmt.Sprintf("%d.%d.%d", major, minor, patch), nil
		}
	}
	return "", fmt.Errorf("could not read version from symbol")
}

// extractMajorMinor returns "X.Y" from a version string like "3.2.1".
func extractMajorMinor(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return version
}
