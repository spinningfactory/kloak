package ebpf

import (
	"debug/buildinfo"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"strings"
)

// GoTLSOffsets contains struct offsets for extracting the GHASH H key from
// Go's crypto/tls internal structures. The layout must match struct
// go_tls_offsets in tls_uprobe.c exactly.
//
// H extraction chain (3 pointer dereferences):
//
//	Conn + ConnToCipher → cipher interface data_ptr → AEAD wrapper
//	  + AEADIfaceOff → inner aead interface data_ptr → GCM struct
//	    + GCMToH → H (16 bytes from productTable[reverseBits(1)])
type GoTLSOffsets struct {
	ConnToCipher uint32 // Conn.out offset + halfConn.cipher offset + 8 (interface data_ptr)
	AEADIfaceOff uint32 // prefixNonceAEAD.aead offset + 8 (interface data_ptr)
	GCMToH       uint32 // GCM.gcmPlatformData + productTable offset + 128 (H index)
	_            uint32 // padding to match BPF struct
}

// goTLSOffsetTable maps Go major.minor versions to struct offsets.
// Discovered by running tools/go-tls-offsets against binaries built
// with each Go version.
//
// TODO: Populate with offsets for Go 1.21, 1.22, 1.23 via the offset tool.
var goTLSOffsetTable = map[string]GoTLSOffsets{
	// Go 1.25/1.26 (FIPS module, gcmPlatformData):
	//   Conn.out=520, halfConn.cipher=32, prefixNonceAEAD.aead=16
	//   GCM.gcmPlatformData=504, gcmPlatformData.productTable=0, H at [8]=128
	//   ConnToCipher = 520 + 32 + 8 = 560
	//   AEADIfaceOff = 16 + 8 = 24
	//   GCMToH = 504 + 0 + 128 = 632
	"1.25": {ConnToCipher: 560, AEADIfaceOff: 24, GCMToH: 632},
	"1.26": {ConnToCipher: 560, AEADIfaceOff: 24, GCMToH: 632},
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
	offsets, ok := goTLSOffsetTable[majorMinor]
	if !ok {
		return bi.GoVersion, GoTLSOffsets{}, fmt.Errorf("unsupported Go version %s (major.minor=%s)", bi.GoVersion, majorMinor)
	}

	return bi.GoVersion, offsets, nil
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

	// 3. GCMToH = path to productTable + 128 (H at index reverseBits(1)=8)
	gcmH, foundH := uint32(0), false

	// Go 1.24+: GCM.gcmPlatformData → gcmPlatformData.productTable
	gcmPD, okPD := getField(structFields, "crypto/internal/fips140/aes/gcm.GCM", "gcmPlatformData")
	pdPT, okPT := getField(structFields, "crypto/internal/fips140/aes/gcm.gcmPlatformData", "productTable")
	if okPD && okPT {
		gcmH = gcmPD + pdPT + 128
		foundH = true
	}

	// Go <1.24: crypto/cipher.gcmAES.productTable
	if !foundH {
		if pt, ok := getField(structFields, "crypto/cipher.gcmAES", "productTable"); ok {
			gcmH = pt + 128
			foundH = true
		}
	}

	if foundH {
		result.GCMToH = gcmH
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
