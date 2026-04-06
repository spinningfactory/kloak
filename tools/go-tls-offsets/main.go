// go-tls-offsets discovers the struct offsets needed by kloak's eBPF code
// to extract the GHASH H key from Go's crypto/tls internal structures.
//
// It reads DWARF debug info from a Go binary and prints the offset chain:
//
//	tls.Conn → halfConn.cipher (interface) → concrete AEAD → gcmAES.productTable → H
//
// Usage:
//
//	go run ./tools/go-tls-offsets /path/to/go-binary
//	go run ./tools/go-tls-offsets  # uses itself as the binary
package main

import (
	"debug/buildinfo"
	"debug/dwarf"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type OffsetResult struct {
	GoVersion        string `json:"go_version"`
	Arch             string `json:"arch"`
	ConnToHalfConn   uint32 `json:"conn_to_half_conn"`
	HalfConnToCipher uint32 `json:"half_conn_to_cipher"`
	CipherDataToGCM  uint32 `json:"cipher_data_to_gcm"`
	GCMToH           uint32 `json:"gcm_to_h"`
	Notes            string `json:"notes,omitempty"`
}

func main() {
	path := os.Args[0]
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	fmt.Fprintf(os.Stderr, "Analyzing: %s\n", path)

	// Read Go build info for version.
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read buildinfo: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "Go version: %s\n", bi.GoVersion)
	}

	f, err := elf.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening ELF: %v\n", err)
		os.Exit(1)
	}

	dw, err := f.DWARF()
	if err != nil {
		_ = f.Close()
		fmt.Fprintf(os.Stderr, "Error reading DWARF: %v\n", err)
		fmt.Fprintf(os.Stderr, "Binary may be stripped (-ldflags='-s -w'). DWARF is required.\n")
		os.Exit(1)
	}
	result := OffsetResult{}
	if bi != nil {
		result.GoVersion = bi.GoVersion
	}
	switch f.Machine {
	case elf.EM_X86_64:
		result.Arch = "amd64"
	case elf.EM_AARCH64:
		result.Arch = "arm64"
	default:
		result.Arch = fmt.Sprintf("unknown(%d)", f.Machine)
	}

	// Walk DWARF entries to find our target structs.
	structs := map[string]map[string]uint32{} // structName -> fieldName -> offset
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
		if !isTargetStruct(name) {
			reader.SkipChildren()
			continue
		}

		fmt.Fprintf(os.Stderr, "\nFound struct: %s\n", name)
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
			// Try DW_AT_data_member_location
			var offset uint32
			if loc, ok := child.Val(dwarf.AttrDataMemberLoc).(int64); ok {
				offset = uint32(loc)
			}
			fields[fieldName] = offset
			fmt.Fprintf(os.Stderr, "  .%s = %d\n", fieldName, offset)
		}

		structs[name] = fields
	}

	// Extract the offsets we need.
	// 1. tls.Conn → out (halfConn, embedded struct)
	if fields, ok := structs["crypto/tls.Conn"]; ok {
		if off, ok := fields["out"]; ok {
			result.ConnToHalfConn = off
			fmt.Fprintf(os.Stderr, "\nConn.out offset: %d\n", off)
		}
	}

	// 2. halfConn → cipher (interface)
	if fields, ok := structs["crypto/tls.halfConn"]; ok {
		if off, ok := fields["cipher"]; ok {
			result.HalfConnToCipher = off
			fmt.Fprintf(os.Stderr, "halfConn.cipher offset: %d\n", off)
		}
	}

	// 3. prefixNonceAEAD → aead (the inner AEAD, typically gcmAES pointer)
	// TLS 1.2 uses prefixNonceAEAD wrapping the actual GCM cipher.
	// TLS 1.3 uses xorNonceAEAD wrapping it.
	// Both have an 'aead' field that is a cipher.AEAD interface.
	for _, structName := range []string{
		"crypto/tls.prefixNonceAEAD",
		"crypto/tls.xorNonceAEAD",
	} {
		if fields, ok := structs[structName]; ok {
			if off, ok := fields["aead"]; ok {
				result.CipherDataToGCM = off
				fmt.Fprintf(os.Stderr, "%s.aead offset: %d\n", structName, off)
				break
			}
		}
	}

	// 4. gcmAES → productTable (the precomputed H powers)
	// productTable is [16][16]byte. H is at index reverseBits(1) = 8, so byte offset 128.
	for _, structName := range []string{
		"crypto/cipher.gcmAES",
		"crypto/internal/fips140/aes/gcm.GCMForSSH",
		"crypto/internal/fips140/aes/gcm.GCM",
	} {
		if fields, ok := structs[structName]; ok {
			if off, ok := fields["productTable"]; ok {
				// H is at productTable[reverseBits(1)] = productTable[8] = offset + 8*16 = offset + 128
				result.GCMToH = off + 128
				fmt.Fprintf(os.Stderr, "%s.productTable offset: %d (H at +128 = %d)\n",
					structName, off, off+128)
				break
			}
		}
	}

	// Check if we got all offsets.
	missing := []string{}
	if result.ConnToHalfConn == 0 {
		missing = append(missing, "Conn.out")
	}
	if result.HalfConnToCipher == 0 {
		missing = append(missing, "halfConn.cipher")
	}
	if result.CipherDataToGCM == 0 {
		missing = append(missing, "prefixNonceAEAD.aead or xorNonceAEAD.aead")
	}
	if result.GCMToH == 0 {
		missing = append(missing, "gcmAES.productTable")
	}
	if len(missing) > 0 {
		result.Notes = fmt.Sprintf("Missing: %s", strings.Join(missing, ", "))
		fmt.Fprintf(os.Stderr, "\nWARNING: missing offsets: %s\n", result.Notes)
		fmt.Fprintf(os.Stderr, "Available structs found:\n")
		for name := range structs {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
	}

	// Output JSON.
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		_ = f.Close()
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
	_ = f.Close()
}

func isTargetStruct(name string) bool {
	targets := []string{
		"crypto/tls.Conn",
		"crypto/tls.halfConn",
		"crypto/tls.prefixNonceAEAD",
		"crypto/tls.xorNonceAEAD",
		"crypto/cipher.gcmAES",
		// Go 1.24+ moved gcm into FIPS module
		"crypto/internal/fips140/aes/gcm.GCMForSSH",
		"crypto/internal/fips140/aes/gcm.GCM",
		"crypto/internal/fips140/aes/gcm.gcmAES",
		"crypto/internal/fips140/aes/gcm.gcmPlatformData",
	}
	for _, t := range targets {
		if name == t {
			return true
		}
	}
	// Also match any struct containing "gcm" or "GCM" for discovery
	if strings.Contains(name, "gcm") || strings.Contains(name, "GCM") {
		return true
	}
	return false
}
