//go:build !cover

package main

// flushCoverage is the production no-op default. The CI build replaces it
// via cmd/kloak/coverage_flush_cover.go (gated by `//go:build cover`),
// which writes covcounters to GOCOVERDIR before the process exits so the
// e2e job can collect a real coverage profile from the controller binary.
//
// In production binaries this file is the only one compiled, so the
// runtime/coverage import isn't pulled in.
var flushCoverage = func() {}
