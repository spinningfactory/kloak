// Build fixture: a tiny Go program that forces the linker to retain the
// crypto/tls structs AND the AES-GCM cipher implementation so DWARF debug
// info still references them after compilation. Used by `tools/go-tls-offsets`
// to discover struct offsets per Go version.
//
// IMPORTANT: merely referencing tls.Conn / tls.Config is not enough — Go
// <1.24's `crypto/cipher.gcmAES` struct is dead-code-eliminated unless an
// AES-GCM cipher is actually constructed somewhere reachable from main.
// We do that below; the binary itself does nothing useful at runtime, only
// the DWARF entries matter.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"fmt"
)

// sink prevents the linker from dead-code-eliminating the references below.
var sink any

func main() {
	// Pull crypto/tls.Conn and friends into the binary (and DWARF).
	sink = &tls.Config{}
	sink = &tls.Conn{}

	// Construct an AES-GCM cipher to force the linker to retain
	// crypto/cipher.gcmAES (Go <1.24) or
	// crypto/internal/fips140/aes/gcm.GCM (Go 1.24+).
	block, err := aes.NewCipher(make([]byte, 16))
	if err == nil {
		if g, err := cipher.NewGCM(block); err == nil {
			sink = g
		}
	}

	fmt.Println("kloak go-tls-offsets fixture")
}
