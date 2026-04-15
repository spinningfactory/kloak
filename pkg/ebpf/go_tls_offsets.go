package ebpf

import (
	"debug/buildinfo"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"runtime"
	"strings"
)

// GoTLSOffsets contains struct offsets for extracting the GHASH H key from
// Go's crypto/tls internal structures. The layout must match struct
// go_tls_offsets in tls_uprobe.c exactly.
//
// H extraction chain (3 pointer dereferences + GF(2^128) halving):
//
//	Conn + ConnToCipher → cipher interface data_ptr → AEAD wrapper
//	  + AEADIfaceOff → inner aead interface data_ptr → GCM struct
//	    + H2HiOff / H2LoOff → H×2 (two 64-bit words from productTable[224])
//
// Go's gcmAesInit assembly computes H = AES_K(0^128), byte-swaps, then
// doubles in GF(2^128) before storing at productTable offset 224. The BPF
// code reads the two words and applies GF halving to recover standard H.
//
// The word order at offset 224 is architecture-dependent:
//   - AMD64 (PSHUFB full reversal): hi word at +8, lo word at +0
//   - ARM64 (VREV64 per-lane reversal): hi word at +0, lo word at +8
type GoTLSOffsets struct {
	ConnToCipher uint32 // Conn.out offset + halfConn.cipher offset + 8 (interface data_ptr)
	AEADIfaceOff uint32 // prefixNonceAEAD.aead offset + 8 (interface data_ptr)
	H2HiOff      uint32 // GCM + off → high 64 bits of H×2 (byte-swapped)
	H2LoOff      uint32 // GCM + off → low 64 bits of H×2 (byte-swapped)
}

// goTLSOffsetTableBase stores architecture-independent offsets plus the
// productTable base offset. The arch-dependent H2 word offsets are computed
// at lookup time by goTLSOffsetsForArch.
type goTLSOffsetEntry struct {
	ConnToCipher uint32
	AEADIfaceOff uint32
	PDBase       uint32 // GCM + gcmPlatformData + productTable + 224 (H×2 entry)
}

// goTLSOffsetTableBase maps Go major.minor versions to base struct offsets.
// Discovered by running tools/go-tls-offsets against binaries built
// with each Go version.
//
// TODO: Populate with offsets for Go 1.21, 1.22, 1.23 via the offset tool.
var goTLSOffsetTableBase = map[string]goTLSOffsetEntry{
	// Go 1.25/1.26 (FIPS module, gcmPlatformData):
	//   Conn.out=520, halfConn.cipher=32, prefixNonceAEAD.aead=16
	//   GCM.gcmPlatformData=504, gcmPlatformData.productTable=0
	//   H×2 at productTable offset 224 → PDBase = 504 + 0 + 224 = 728
	//   ConnToCipher = 520 + 32 + 8 = 560
	//   AEADIfaceOff = 16 + 8 = 24
	"1.25": {ConnToCipher: 560, AEADIfaceOff: 24, PDBase: 728},
	"1.26": {ConnToCipher: 560, AEADIfaceOff: 24, PDBase: 728},
}

// goTLSOffsetsForArch converts a base entry to arch-specific GoTLSOffsets
// by applying the correct word order for the H×2 entry.
//
// AMD64 PSHUFB (full 16-byte reversal): hi word at +8, lo word at +0
// ARM64 VREV64 (per-lane 8-byte reversal): hi word at +0, lo word at +8
func goTLSOffsetsForArch(entry goTLSOffsetEntry, goarch string) GoTLSOffsets {
	o := GoTLSOffsets{
		ConnToCipher: entry.ConnToCipher,
		AEADIfaceOff: entry.AEADIfaceOff,
	}
	switch goarch {
	case "amd64":
		o.H2HiOff = entry.PDBase + 8
		o.H2LoOff = entry.PDBase + 0
	default: // arm64 and others with per-lane byte reversal
		o.H2HiOff = entry.PDBase + 0
		o.H2LoOff = entry.PDBase + 8
	}
	return o
}

// DetectGoTLSOffsets reads a Go binary and returns the struct offsets needed
// for H extraction. Tries DWARF first, then falls back to version-based lookup.
func DetectGoTLSOffsets(exePath string) (version string, offsets GoTLSOffsets, err error) {
	// Try DWARF-based detection first.
	version, offsets, err = detectGoTLSFromDWARF(exePath)
	if err == nil {
		return version, offsets, nil
	}

	// Fall back to buildinfo version lookup.
	return detectGoTLSByVersion(exePath)
}

func detectGoTLSByVersion(exePath string) (string, GoTLSOffsets, error) {
	bi, err := buildinfo.ReadFile(exePath)
	if err != nil {
		return "", GoTLSOffsets{}, fmt.Errorf("reading buildinfo from %s: %w", exePath, err)
	}

	majorMinor := extractGoMajorMinor(bi.GoVersion)
	entry, ok := goTLSOffsetTableBase[majorMinor]
	if !ok {
		return bi.GoVersion, GoTLSOffsets{}, fmt.Errorf("unsupported Go version %s (major.minor=%s)", bi.GoVersion, majorMinor)
	}

	// Determine target architecture from the ELF binary, not the host.
	goarch, err := elfGoArch(exePath)
	if err != nil {
		goarch = runtime.GOARCH // fallback to host arch
	}

	return bi.GoVersion, goTLSOffsetsForArch(entry, goarch), nil
}

// elfGoArch returns the GOARCH string for an ELF binary.
func elfGoArch(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	switch f.Machine {
	case elf.EM_X86_64:
		return "amd64", nil
	case elf.EM_AARCH64:
		return "arm64", nil
	default:
		return "", fmt.Errorf("unknown ELF machine %v", f.Machine)
	}
}

func detectGoTLSFromDWARF(exePath string) (string, GoTLSOffsets, error) {
	f, err := elf.Open(exePath)
	if err != nil {
		return "", GoTLSOffsets{}, fmt.Errorf("opening ELF %s: %w", exePath, err)
	}
	defer func() { _ = f.Close() }()

	dw, err := f.DWARF()
	if err != nil {
		return "", GoTLSOffsets{}, fmt.Errorf("reading DWARF from %s: %w", exePath, err)
	}

	// Get Go version from buildinfo.
	var goVersion string
	bi, err := buildinfo.ReadFile(exePath)
	if err == nil {
		goVersion = bi.GoVersion
	}

	// Walk DWARF to find our target structs.
	structFields := map[string]map[string]uint32{}
	reader := dw.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag != dwarf.TagStructType {
			continue
		}
		name, _ := entry.Val(dwarf.AttrName).(string)
		if !isGoTLSTargetStruct(name) {
			reader.SkipChildren()
			continue
		}

		fields := map[string]uint32{}
		for {
			child, err := reader.Next()
			if err != nil || child == nil || child.Tag == 0 {
				break
			}
			if child.Tag != dwarf.TagMember {
				continue
			}
			fieldName, _ := child.Val(dwarf.AttrName).(string)
			if loc, ok := child.Val(dwarf.AttrDataMemberLoc).(int64); ok {
				fields[fieldName] = uint32(loc)
			}
		}
		structFields[name] = fields
	}

	// Extract the 3 combined offsets.
	var result GoTLSOffsets
	var missing []string

	// 1. ConnToCipher = Conn.out + halfConn.cipher + 8 (interface data_ptr)
	connOut, ok1 := getField(structFields, "crypto/tls.Conn", "out")
	cipherOff, ok2 := getField(structFields, "crypto/tls.halfConn", "cipher")
	if ok1 && ok2 {
		result.ConnToCipher = connOut + cipherOff + 8
	} else {
		missing = append(missing, "Conn.out or halfConn.cipher")
	}

	// 2. AEADIfaceOff = prefixNonceAEAD.aead (or xorNonceAEAD.aead) + 8
	aeadOff, found := uint32(0), false
	for _, sn := range []string{"crypto/tls.prefixNonceAEAD", "crypto/tls.xorNonceAEAD"} {
		if off, ok := getField(structFields, sn, "aead"); ok {
			aeadOff = off
			found = true
			break
		}
	}
	if found {
		result.AEADIfaceOff = aeadOff + 8
	} else {
		missing = append(missing, "prefixNonceAEAD.aead")
	}

	// 3. H×2 word offsets from productTable offset 224.
	// gcmAesInit stores H×2 (H doubled in GF(2^128)) at productTable[224].
	// The two 64-bit words are in different order on AMD64 vs ARM64.
	pdBase, foundPD := uint32(0), false

	// Go 1.24+: GCM.gcmPlatformData → gcmPlatformData.productTable
	gcmPD, okPD := getField(structFields, "crypto/internal/fips140/aes/gcm.GCM", "gcmPlatformData")
	pdPT, okPT := getField(structFields, "crypto/internal/fips140/aes/gcm.gcmPlatformData", "productTable")
	if okPD && okPT {
		pdBase = gcmPD + pdPT + 224 // H×2 at entry 14 (offset 224 within productTable)
		foundPD = true
	}

	// Go <1.24: crypto/cipher.gcmAES.productTable
	if !foundPD {
		if pt, ok := getField(structFields, "crypto/cipher.gcmAES", "productTable"); ok {
			pdBase = pt + 224
			foundPD = true
		}
	}

	// Go 1.25+ non-FIPS, hardware AES: crypto/aes.gcmAsm.productTable
	if !foundPD {
		if pt, ok := getField(structFields, "crypto/aes.gcmAsm", "productTable"); ok {
			pdBase = pt + 224
			foundPD = true
		}
	}

	// Go 1.25+ non-FIPS, software AES: crypto/cipher.gcm.productTable
	if !foundPD {
		if pt, ok := getField(structFields, "crypto/cipher.gcm", "productTable"); ok {
			pdBase = pt + 224
			foundPD = true
		}
	}

	if foundPD {
		// Determine target architecture from the ELF binary.
		goarch := ""
		switch f.Machine {
		case elf.EM_X86_64:
			goarch = "amd64"
		case elf.EM_AARCH64:
			goarch = "arm64"
		}
		if goarch == "amd64" {
			// PSHUFB full 16-byte reversal: hi word at +8, lo word at +0
			result.H2HiOff = pdBase + 8
			result.H2LoOff = pdBase + 0
		} else {
			// ARM64 VREV64 per-lane reversal: hi word at +0, lo word at +8
			result.H2HiOff = pdBase + 0
			result.H2LoOff = pdBase + 8
		}
	} else {
		missing = append(missing, "gcmAES.productTable")
	}

	if len(missing) > 0 {
		return goVersion, result, fmt.Errorf("missing DWARF offsets: %s", strings.Join(missing, ", "))
	}

	return goVersion, result, nil
}

func getField(structFields map[string]map[string]uint32, structName, fieldName string) (uint32, bool) {
	fields, ok := structFields[structName]
	if !ok {
		return 0, false
	}
	off, ok := fields[fieldName]
	return off, ok
}

func isGoTLSTargetStruct(name string) bool {
	targets := []string{
		"crypto/tls.Conn",
		"crypto/tls.halfConn",
		"crypto/tls.prefixNonceAEAD",
		"crypto/tls.xorNonceAEAD",
		"crypto/cipher.gcmAES",
		"crypto/aes.gcmAsm",
		"crypto/cipher.gcm",
		"crypto/internal/fips140/aes/gcm.GCM",
		"crypto/internal/fips140/aes/gcm.gcmPlatformData",
	}
	for _, t := range targets {
		if name == t {
			return true
		}
	}
	return false
}

// extractGoMajorMinor returns "1.25" from "go1.25.1" or "go1.25".
func extractGoMajorMinor(version string) string {
	v := strings.TrimPrefix(version, "go")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}
