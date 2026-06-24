//go:build cover

package main

import (
	"fmt"
	"os"
	"runtime/coverage"
)

// Compiled in only via `-tags cover` (set by install.sh when
// `KLOAK_COVER=1` is in env; CI's Krunk E2E job sets it before invoking
// install.sh so the cap'd krunk binary contributes runtime coverage
// data back to the merged profile). runtime/coverage.WriteCountersDir
// writes covcounters explicitly, independent of Go's exit-hook chain
// — empirically Go's automatic flush hasn't been reliable in the
// e2e environment for the kloak daemon, so we mirror that pattern
// here for krunk.
//
// The file is compiled out of production binaries, so the
// runtime/coverage import does not appear in the production symbol
// table.
var flushCoverage = func() {
	dir := os.Getenv("GOCOVERDIR")
	if dir == "" {
		fmt.Fprintln(os.Stderr, "krunk: flushCoverage skipped — GOCOVERDIR unset")
		return
	}
	if err := coverage.WriteCountersDir(dir); err != nil {
		fmt.Fprintf(os.Stderr, "krunk: flushCoverage failed dir=%s err=%v\n", dir, err)
		return
	}
	fmt.Fprintf(os.Stderr, "krunk: flushCoverage wrote covcounters to %s\n", dir)
}
