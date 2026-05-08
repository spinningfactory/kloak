// go-tls-offsets discovers the struct offsets needed by kloak's eBPF code
// to extract the GHASH H key from Go's crypto/tls internal structures.
//
// It reads DWARF debug info from a Go binary and prints the offset chain:
//
//	tls.Conn → halfConn.cipher (interface) → AEAD wrapper → GCM.productTable → H×2
//
// The output matches the go_tls_offsets struct in tls_uprobe.c:
//   - conn_to_cipher: combined offset to cipher interface data_ptr
//   - aead_iface_off: offset to inner aead interface data_ptr
//   - h2_hi_off: GCM offset to high 64-bit word of H×2
//   - h2_lo_off: GCM offset to low 64-bit word of H×2
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

// OffsetResult matches the go_tls_offsets BPF struct layout.
type OffsetResult struct {
	GoVersion    string `json:"go_version"`
	Arch         string `json:"arch"`
	ConnToCipher uint32 `json:"conn_to_cipher"` // Conn.out + halfConn.cipher + 8
	AEADIfaceOff uint32 `json:"aead_iface_off"` // prefixNonceAEAD.aead + 8
	H2HiOff      uint32 `json:"h2_hi_off"`      // GCM + off → high 64 bits of H×2
	H2LoOff      uint32 `json:"h2_lo_off"`      // GCM + off → low 64 bits of H×2
	ConnVersOff  uint32 `json:"conn_vers_off"`  // Conn.vers (uint16 TLS version)
	Notes        string `json:"notes,omitempty"`

	// Raw offsets for debugging (not used by BPF).
	Raw struct {
		ConnOut      uint32 `json:"conn_out"`
		CipherOff    uint32 `json:"cipher_off"`
		AEADOff      uint32 `json:"aead_off"`
		ProductTable uint32 `json:"product_table"`
		PDBase       uint32 `json:"pd_base"` // productTable + 224 (H×2 entry)
	} `json:"raw"`
}

func main() {
	path := os.Args[0]
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	fmt.Fprintf(os.Stderr, "Analyzing: %s\n", path)

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

	// Walk DWARF entries to find target structs.
	structs := map[string]map[string]uint32{}
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
			var offset uint32
			if loc, ok := child.Val(dwarf.AttrDataMemberLoc).(int64); ok {
				offset = uint32(loc)
			}
			fields[fieldName] = offset
			fmt.Fprintf(os.Stderr, "  .%s = %d\n", fieldName, offset)
		}
		structs[name] = fields
	}

	// Compute combined offsets matching BPF struct layout.
	var missing []string

	// 1. ConnToCipher = Conn.out + halfConn.cipher + 8 (interface data_ptr)
	connOut, ok1 := getField(structs, "crypto/tls.Conn", "out")
	cipherOff, ok2 := getField(structs, "crypto/tls.halfConn", "cipher")
	if ok1 && ok2 {
		result.Raw.ConnOut = connOut
		result.Raw.CipherOff = cipherOff
		result.ConnToCipher = connOut + cipherOff + 8
		fmt.Fprintf(os.Stderr, "\nConnToCipher = %d + %d + 8 = %d\n", connOut, cipherOff, result.ConnToCipher)
	} else {
		missing = append(missing, "Conn.out or halfConn.cipher")
	}

	// 2. AEADIfaceOff = prefixNonceAEAD.aead (or xorNonceAEAD.aead) + 8
	for _, sn := range []string{"crypto/tls.prefixNonceAEAD", "crypto/tls.xorNonceAEAD"} {
		if off, ok := getField(structs, sn, "aead"); ok {
			result.Raw.AEADOff = off
			result.AEADIfaceOff = off + 8
			fmt.Fprintf(os.Stderr, "AEADIfaceOff = %d + 8 = %d (from %s)\n", off, result.AEADIfaceOff, sn)
			break
		}
	}
	if result.AEADIfaceOff == 0 {
		missing = append(missing, "prefixNonceAEAD.aead or xorNonceAEAD.aead")
	}

	// ConnVersOff = Conn.vers (uint16 — negotiated TLS version, e.g. 0x0303).
	// Not strictly required by the data plane (tc_egress falls back to a
	// plaintext_len heuristic when 0xFFFFFFFF), but the table carries it for
	// determinism. Emit only if DWARF has it.
	if versOff, ok := getField(structs, "crypto/tls.Conn", "vers"); ok {
		result.ConnVersOff = versOff
		fmt.Fprintf(os.Stderr, "ConnVersOff = %d (Conn.vers)\n", versOff)
	}

	// 3. H×2 word offsets from productTable.
	// gcmAesInit stores H×2 (H doubled in GF(2^128)) at productTable offset 224.
	// The two 64-bit words have architecture-dependent order:
	//   AMD64 PSHUFB: hi at +8, lo at +0
	//   ARM64 VREV64: hi at +0, lo at +8
	pdBase, foundPD := uint32(0), false

	// Go 1.24+: GCM.gcmPlatformData → gcmPlatformData.productTable
	gcmPD, okPD := getField(structs, "crypto/internal/fips140/aes/gcm.GCM", "gcmPlatformData")
	pdPT, okPT := getField(structs, "crypto/internal/fips140/aes/gcm.gcmPlatformData", "productTable")
	if okPD && okPT {
		pdBase = gcmPD + pdPT + 224
		foundPD = true
		fmt.Fprintf(os.Stderr, "PDBase = GCM.gcmPlatformData(%d) + productTable(%d) + 224 = %d\n", gcmPD, pdPT, pdBase)
	}

	// Go <1.24: prefer crypto/aes.gcmAsm — the AES-NI/PCLMULQDQ-optimized
	// path that crypto/cipher.NewGCM(aesBlock) actually returns at runtime
	// when the CPU supports it. crypto/cipher.gcm is the SOFTWARE FALLBACK
	// used only when the cipher.Block doesn't implement gcmAble; the AEAD
	// interface in a normal TLS process points to *gcmAsm, not *gcm. Old
	// versions of this tool used cipher.gcm offsets and produced offsets
	// that were correct for the dead fallback type but wrong for the
	// runtime type — `pd_base` was off by 8 bytes (cipher.gcm has its
	// productTable at offset 32 after a 16-byte cipher iface; gcmAsm has
	// it at offset 24 after a 24-byte slice header `ks []uint32`). That
	// 8-byte miss made BPF read garbage, fail GMAC, and silently drop
	// every rewrite for Go 1.20–1.23 demos.
	//
	// `gcmAES` / `gcmAESCBC` are kept as forward-compat hooks; if a future
	// Go ships either, fall back to them (and finally to crypto/cipher.gcm
	// for builds without AES-NI, where the fallback type IS the runtime
	// type — those produce correct offsets too).
	if !foundPD {
		for _, sn := range []string{
			"crypto/aes.gcmAsm",
			"crypto/aes.gcmAES",
			"crypto/cipher.gcmAES",
			"crypto/cipher.gcmAsm",
			"crypto/cipher.gcm", // software-fallback path (no AES-NI)
		} {
			if pt, ok := getField(structs, sn, "productTable"); ok {
				pdBase = pt + 224
				foundPD = true
				fmt.Fprintf(os.Stderr, "PDBase = %s.productTable(%d) + 224 = %d\n", sn, pt, pdBase)
				break
			}
		}
	}

	if foundPD {
		result.Raw.ProductTable = pdBase - 224
		result.Raw.PDBase = pdBase
		if result.Arch == "amd64" {
			result.H2HiOff = pdBase + 8
			result.H2LoOff = pdBase
		} else {
			result.H2HiOff = pdBase
			result.H2LoOff = pdBase + 8
		}
		fmt.Fprintf(os.Stderr, "H2HiOff = %d, H2LoOff = %d (arch=%s)\n", result.H2HiOff, result.H2LoOff, result.Arch)
	} else {
		missing = append(missing, "productTable")
	}

	if len(missing) > 0 {
		result.Notes = fmt.Sprintf("Missing: %s", strings.Join(missing, ", "))
		fmt.Fprintf(os.Stderr, "\nWARNING: missing offsets: %s\n", result.Notes)
		fmt.Fprintf(os.Stderr, "Available structs found:\n")
		for name := range structs {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		_ = f.Close()
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
	_ = f.Close()
}

func getField(structs map[string]map[string]uint32, structName, fieldName string) (uint32, bool) {
	fields, ok := structs[structName]
	if !ok {
		return 0, false
	}
	off, ok := fields[fieldName]
	return off, ok
}

func isTargetStruct(name string) bool {
	targets := []string{
		"crypto/tls.Conn",
		"crypto/tls.halfConn",
		"crypto/tls.prefixNonceAEAD",
		"crypto/tls.xorNonceAEAD",
		// Go 1.20–1.23: AES-NI runtime type lives in crypto/aes; crypto/cipher
		// types are the software fallback used when AES-NI is unavailable.
		"crypto/aes.gcmAsm",
		"crypto/aes.gcmAES",
		"crypto/cipher.gcm",
		"crypto/cipher.gcmAES",
		"crypto/cipher.gcmAsm",
		// Go 1.24+: GCM struct moved into the FIPS 140 module.
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
	// Also match any struct containing "gcm" or "GCM" for discovery.
	if strings.Contains(name, "gcm") || strings.Contains(name, "GCM") {
		return true
	}
	return false
}
