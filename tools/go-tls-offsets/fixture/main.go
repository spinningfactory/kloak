// Build fixture: a tiny Go program that forces the linker to retain
// crypto/tls and the GCM struct so DWARF debug info still references them
// after compilation. Used by `tools/go-tls-offsets` to discover struct
// offsets per Go version.
//
// The binary itself does nothing useful at runtime; only the symbol table
// and DWARF entries matter.
package main

import (
	"crypto/tls"
	"fmt"
)

// sink prevents the linker from dead-code-eliminating the references below.
var sink any

func main() {
	cfg := &tls.Config{}
	sink = cfg
	sink = &tls.Conn{}
	fmt.Println("kloak go-tls-offsets fixture")
}
