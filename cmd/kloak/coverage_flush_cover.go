//go:build cover

package main

import (
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
		return
	}
	_ = coverage.WriteCountersDir(dir)
}
