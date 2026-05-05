// Standalone module so the fixture can compile with older Go toolchains.
// The parent kloak module requires `go 1.26.0`, which would fail to build
// with `golang:1.20`. Keep this floor at the oldest supported version.
module fixture

go 1.20
