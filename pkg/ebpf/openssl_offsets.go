package ebpf

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"strings"
)

// TLSOffsets contains struct offsets for reading TLS key material from an SSL*
// object at runtime. These offsets are version-specific and must match the
// OpenSSL build used in the container.
type TLSOffsets struct {
	// GHashH is the offset from SSL* to the GHASH key H (16 bytes).
	// Path: SSL* → enc_write_ctx (EVP_CIPHER_CTX*) → GCM context → Htable[0]
	GHashH uint32

	// CipherID is the offset from SSL* to the negotiated cipher suite ID.
	// Path: SSL* → s3 → tmp.new_cipher → id (uint32, but we read 2 bytes
	// for the TLS cipher suite value).
	CipherID uint32
}

// opensslOffsetTable maps OpenSSL major.minor version strings to their TLS
// struct offsets. These offsets are determined by compiling OpenSSL at each
// version and inspecting the struct layouts with pahole/gdb.
//
// The offsets account for the chained pointer dereferences:
//   SSL* → enc_write_ctx → cipher_data (EVP_AES_GCM_CTX) → gcm.Htable
//
// Since these are multi-level pointer dereferences, we store them as a chain
// of offsets that the eBPF code follows step by step. However, for the initial
// implementation, we flatten to a single "effective offset" by pre-reading
// the intermediate pointers in userspace and pushing the final address offset.
//
// TODO: These offsets need validation against each OpenSSL version.
// The current values are placeholders derived from OpenSSL 3.0 source analysis
// and must be verified via pahole or runtime testing before production use.
var opensslOffsetTable = map[string]TLSOffsets{
	// OpenSSL 3.0.x (Ubuntu 22.04, Debian Bookworm)
	"3.0": {GHashH: 0, CipherID: 0},
	// OpenSSL 3.1.x
	"3.1": {GHashH: 0, CipherID: 0},
	// OpenSSL 3.2.x (Ubuntu 24.04)
	"3.2": {GHashH: 0, CipherID: 0},
	// OpenSSL 3.3.x
	"3.3": {GHashH: 0, CipherID: 0},
	// OpenSSL 3.4.x
	"3.4": {GHashH: 0, CipherID: 0},
	// OpenSSL 3.5.x
	"3.5": {GHashH: 0, CipherID: 0},
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
	defer f.Close()

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

	if offsets.GHashH == 0 {
		return version, offsets, fmt.Errorf("OpenSSL %s offsets not yet calibrated (GHashH=0)", version)
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
				return readVersionFromSymbol(f, sym)
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
func readVersionFromSymbol(f *elf.File, sym elf.Symbol) (string, error) {
	// For OpenSSL 3.x, the version_num function returns a value, not a constant.
	// We can try to read from the .data section at the symbol's address.
	for _, sec := range f.Sections {
		if sec.Addr <= sym.Value && sym.Value < sec.Addr+sec.Size {
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
