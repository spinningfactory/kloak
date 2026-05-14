//go:build !linux

package ebpf

// Non-Linux stub for the eBPF uprobe manager. The real implementation in
// uprobe.go depends on `github.com/cilium/ebpf`, `unix.Setns`, and
// uprobe attachment via /sys/kernel/tracing/uprobe_events — all of
// which exist only on Linux.
//
// This file exists so the rest of the codebase (pkg/controller,
// cmd/kloak, anything transitively importing pkg/ebpf) compiles on
// macOS and other non-Linux dev environments, allowing `go vet ./...`
// and `go test ./pkg/secrets/... ./pkg/storage/... ./pkg/webhook/...`
// to run locally without needing a Linux VM.
//
// Every method returns errNotSupported (no-op for the void methods).
// Callers must handle this gracefully on non-Linux; the production
// controller entrypoint (`kloak controller`) refuses to run on
// non-Linux anyway, so these stubs are exercised only by tests and
// `go vet`.

import (
	"context"
	"errors"
	"net"

	"go.uber.org/zap"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

var errNotSupported = errors.New("kloak: eBPF uprobes are only supported on Linux")

// TLSUprobeManager is the public type the rest of the codebase holds.
// On non-Linux it's an empty struct — every method returns
// errNotSupported (or is a no-op for the void methods).
type TLSUprobeManager struct{}

func NewTLSUprobeManager(_ secrets.Source, _ string, _ *zap.SugaredLogger) (*TLSUprobeManager, error) {
	return nil, errNotSupported
}

func (m *TLSUprobeManager) TrackTGID(uint32) error                   { return errNotSupported }
func (m *TLSUprobeManager) UntrackTGID(uint32) error                 { return errNotSupported }
func (m *TLSUprobeManager) TrackCgroup(uint64, string) error         { return errNotSupported }
func (m *TLSUprobeManager) RecordCgroupNetns(uint64, int)            {}
func (m *TLSUprobeManager) UntrackCgroup(uint64) error               { return errNotSupported }
func (m *TLSUprobeManager) AttachTLS(int, uint64) error              { return errNotSupported }
func (m *TLSUprobeManager) Close() error                             { return errNotSupported }
func (m *TLSUprobeManager) PollExecEvents(context.Context) error     { return errNotSupported }
func (m *TLSUprobeManager) PollEvents(context.Context) error         { return errNotSupported }
func (m *TLSUprobeManager) PopulateTrustedDNSServers([]net.IP) error { return errNotSupported }
func (m *TLSUprobeManager) DumpDebugCounters()                       {}
