//go:build cover

package main

import (
	"fmt"
	"os"
	"runtime/coverage"
)

// Compiled in only via `-tags cover` (see Dockerfile, COVER=1 branch).
// runtime/coverage.WriteCountersDir writes covcounters explicitly,
// independent of Go's exit-hook chain — which empirically wasn't firing
// in our e2e environment, leaving the badge stuck on unit-only coverage.
//
// The file is compiled out of production binaries, so the runtime/coverage
// import does not appear in the production symbol table.
var flushCoverage = func() {
	dir := os.Getenv("GOCOVERDIR")
	if dir == "" {
		fmt.Fprintln(os.Stderr, "kloak: flushCoverage skipped — GOCOVERDIR unset")
		return
	}
	if err := coverage.WriteCountersDir(dir); err != nil {
		fmt.Fprintf(os.Stderr, "kloak: flushCoverage failed dir=%s err=%v\n", dir, err)
		return
	}
	fmt.Fprintf(os.Stderr, "kloak: flushCoverage wrote covcounters to %s\n", dir)
}
