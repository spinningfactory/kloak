//go:build !cover

package main

// flushCoverage is the production no-op default. The CI / install.sh
// `KLOR_COVER=1` path replaces it via coverage_flush_cover.go (gated
// by `//go:build cover`), which writes covcounters to `$GOCOVERDIR`
// before the process exits so the Klor E2E CI job can collect a real
// coverage profile from the cap'd binary.
//
// In production binaries this file is the only one compiled, so the
// runtime/coverage import isn't pulled in.
var flushCoverage = func() {}
