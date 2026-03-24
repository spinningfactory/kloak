package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/spinningfactory/kloak/pkg/storage"
)

// tlsEvent must match the C struct tls_event (lightweight, no data payload)
type tlsEvent struct {
	Pid         uint32
	Tgid        uint32
	Len         uint32
	IsRewritten uint8
	_           [3]byte // padding for alignment
}

// secretKey matches C struct secret_key (SECRET_KEY_LEN = 8)
type secretKey struct {
	Prefix [8]byte
}

// secretValue matches C struct secret_value
type secretValue struct {
	Len         uint32
	RealSecret  [128]byte
	HostLen     uint32
	AllowedHost [32]byte
	PrefixLen   uint32
	FullPrefix  [42]byte // SECRET_PREFIX_MAX
	_           [2]byte  // padding to match C struct alignment
}

// watchedHostKey matches C struct watched_host_key
type watchedHostKey struct {
	Host [32]byte
}

// Generate eBPF bindings. The KLOAK_TARGET_ARCH env var (set by Dockerfile or
// Makefile) controls which __TARGET_ARCH_xxx define is passed to clang.
// Defaults to arm64 for local development on macOS/Lima.
//go:generate sh -c "ARCH=${KLOAK_TARGET_ARCH:-arm64}; go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags \"-O2 -g -Wall -Werror -D__TARGET_ARCH_${ARCH}\" tlsuprobe bpf/tls_uprobe.c -- -I../ebpf"

// TLSUprobeManager manages the loading and attaching of eBPF uprobes for TLS interception.
type TLSUprobeManager struct {
	objs   *tlsuprobeObjects
	reader *ringbuf.Reader
	log    logr.Logger
	links  []link.Link

	// store provides access to secrets
	store storage.Storage
}

// NewTLSUprobeManager initializes a new uprobe manager.
func NewTLSUprobeManager(store storage.Storage) (*TLSUprobeManager, error) {
	log := ctrl.Log.WithName("ebpf-uprobe")

	objs := &tlsuprobeObjects{}
	// First attempt: no verifier log (avoids large memory allocation).
	if err := loadTlsuprobeObjects(objs, nil); err != nil {
		// Retry with verifier log on failure to capture diagnostics.
		opts := &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogLevel:     ebpf.LogLevelBranch,
				LogSizeStart: 1 << 20, // 1MB — bpf_loop callbacks generate large logs
			},
		}
		if retryErr := loadTlsuprobeObjects(objs, opts); retryErr != nil {
			var ve *ebpf.VerifierError
			if errors.As(retryErr, &ve) {
				log.Error(retryErr, "eBPF Verifier Error", "verifier_log", fmt.Sprintf("%+v", ve))
			}
			return nil, fmt.Errorf("loading eBPF objects: %w", retryErr)
		}
	}

	// Wire up tail call map: index 0 -> bpf_phase2_rewrite
	fd := uint32(objs.BpfPhase2Rewrite.FD())
	if err := objs.ProgArray.Put(uint32(0), fd); err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("configuring tail call map: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.TlsEvents)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}

	mgr := &TLSUprobeManager{
		objs:   objs,
		reader: reader,
		log:    log,
		store:  store,
	}

	// Attach tracepoints for DNS interception and connect tracking.
	// These are system-wide but filtered per-process via tracked_tgids map.
	if err := mgr.attachTracepoints(); err != nil {
		_ = mgr.Close()
		return nil, fmt.Errorf("attaching tracepoints: %w", err)
	}

	return mgr, nil
}

// attachTracepoints attaches the syscall tracepoints and kprobes for DNS and connect tracking.
func (m *TLSUprobeManager) attachTracepoints() error {
	type tp struct {
		group string
		name  string
		prog  *ebpf.Program
	}

	tracepoints := []tp{
		{"syscalls", "sys_enter_connect", m.objs.TpEnterConnect},
		{"syscalls", "sys_exit_connect", m.objs.TpExitConnect},
	}

	for _, t := range tracepoints {
		l, err := link.Tracepoint(t.group, t.name, t.prog, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint %s/%s: %w", t.group, t.name, err)
		}
		m.links = append(m.links, l)
		m.log.Info("Attached tracepoint", "group", t.group, "name", t.name)
	}

	// Attach kprobe/kretprobe on udp_recvmsg for language-agnostic DNS interception.
	kp, err := link.Kprobe("udp_recvmsg", m.objs.KprobeUdpRecvmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe udp_recvmsg: %w", err)
	}
	m.links = append(m.links, kp)
	m.log.Info("Attached kprobe", "function", "udp_recvmsg")

	krp, err := link.Kretprobe("udp_recvmsg", m.objs.KretprobeUdpRecvmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe udp_recvmsg: %w", err)
	}
	m.links = append(m.links, krp)
	m.log.Info("Attached kretprobe", "function", "udp_recvmsg")

	return nil
}

// TrackTGID adds a process TGID to the tracked_tgids map, enabling
// DNS/connect tracepoint processing for that process.
func (m *TLSUprobeManager) TrackTGID(tgid uint32) error {
	val := uint8(1)
	return m.objs.TrackedTgids.Update(tgid, &val, 0)
}

// UntrackTGID removes a process TGID from the tracked_tgids map.
func (m *TLSUprobeManager) UntrackTGID(tgid uint32) error {
	return m.objs.TrackedTgids.Delete(tgid)
}

// AttachTLS attempts to automatically detect the runtime language and attach
// the correct eBPF uprobes (Go crypto/tls or OpenSSL) to the given PID.
// Also registers the PID's TGID in tracked_tgids for DNS/connect tracking.
func (m *TLSUprobeManager) AttachTLS(pid int) error {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	// Register the process for DNS/connect tracking.
	// On Linux, PID == TGID for the main thread.
	if err := m.TrackTGID(uint32(pid)); err != nil {
		m.log.Error(err, "failed to track TGID for DNS/connect", "pid", pid)
		// Non-fatal: continue with uprobe attachment
	} else {
		m.log.Info("Tracking TGID for DNS/connect verification", "pid", pid)
	}

	// Open the executable to figure out if it's Go or uses OpenSSL
	ex, err := link.OpenExecutable(exePath)
	if err != nil {
		return fmt.Errorf("opening executable %s: %w", exePath, err)
	}

	// 1. Try Go crypto/tls first
	// We check if the symbol exists in the binary.
	goWriteSym := "crypto/tls.(*Conn).Write"
	upGo, err := ex.Uprobe(goWriteSym, m.objs.BpfUprobeGoTlsWrite, nil)
	if err == nil {
		m.log.Info("Attached Go uprobe to process", "pid", pid, "symbol", goWriteSym)
		m.links = append(m.links, upGo)
		return nil
	} else if !errors.Is(err, link.ErrNoSymbol) && !strings.Contains(err.Error(), "no symbol") {
		// Log errors that are NOT just "symbol missing"
		m.log.Error(err, "failed to attach Go uprobe, but symbol may exist")
	}

	// 2. Try OpenSSL / BoringSSL (Node.js, Python, Rust, Envoy, gRPC)
	// Modern OpenSSL 3.x and BoringSSL export both SSL_write and SSL_write_ex
	// with identical C ABI calling convention.
	sslWriteSymbols := []string{"SSL_write", "SSL_write_ex"}
	attached := false

	// Try main executable first (catches statically linked BoringSSL/OpenSSL)
	for _, sym := range sslWriteSymbols {
		up, err := ex.Uprobe(sym, m.objs.BpfUprobeSslWrite, nil)
		if err == nil {
			m.log.Info("Attached SSL write uprobe to main exe", "pid", pid, "symbol", sym)
			m.links = append(m.links, up)
			attached = true
		}
	}

	// Try all TLS shared libraries found in the process maps
	for _, libPath := range findTLSLibraries(pid) {
		libEx, err := link.OpenExecutable(libPath)
		if err != nil {
			continue
		}
		for _, sym := range sslWriteSymbols {
			up, err := libEx.Uprobe(sym, m.objs.BpfUprobeSslWrite, nil)
			if err == nil {
				m.log.Info("Attached SSL write uprobe to shared library", "pid", pid, "symbol", sym, "lib", libPath)
				m.links = append(m.links, up)
				attached = true
			}
		}
	}

	if attached {
		return nil
	}

	return fmt.Errorf("could not find compatible TLS symbols for PID %d", pid)
}

// findTLSLibraries scans /proc/<pid>/maps for shared libraries that may export
// SSL_write: OpenSSL (libssl.so), BoringSSL (libboringssl.so or libssl.so),
// and libcrypto.so (some BoringSSL builds export SSL_write there).
// Returns deduplicated paths accessible via /proc/<pid>/root.
func findTLSLibraries(pid int) []string {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var libs []string

	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		path := parts[len(parts)-1]
		if !strings.HasPrefix(path, "/") {
			continue
		}
		// Match any shared library that could export SSL_write
		base := path[strings.LastIndex(path, "/")+1:]
		if !isTLSLibrary(base) {
			continue
		}
		fullPath := fmt.Sprintf("/proc/%d/root%s", pid, path)
		if !seen[fullPath] {
			seen[fullPath] = true
			libs = append(libs, fullPath)
		}
	}
	return libs
}

// isTLSLibrary returns true if the filename looks like an SSL/TLS shared library.
func isTLSLibrary(name string) bool {
	// OpenSSL and BoringSSL shared builds
	if strings.HasPrefix(name, "libssl.so") {
		return true
	}
	// Custom BoringSSL builds
	if strings.HasPrefix(name, "libboringssl.so") {
		return true
	}
	// Some BoringSSL builds export SSL_write from libcrypto
	if strings.HasPrefix(name, "libcrypto.so") {
		return true
	}
	return false
}

// Close releases all links and the eBPF manager.
func (m *TLSUprobeManager) Close() error {
	var errs []error
	for _, l := range m.links {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	m.links = nil

	if m.reader != nil {
		if err := m.reader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.objs != nil {
		if err := m.objs.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing uprobe manager: %v", errs)
	}
	return nil
}

// PollEvents reads TLS events from the ring buffer and periodically syncs secrets to the eBPF map.
func (m *TLSUprobeManager) PollEvents(ctx context.Context) error {
	m.log.Info("Starting eBPF TLS event poller and secret syncer")

	// Trigger an initial sync
	m.syncSecretsToBPF()

	// Periodic re-sync ticker. The initial sync may have found an empty store
	// (secret reconciler hasn't run yet), so we must keep re-syncing.
	syncTicker := time.NewTicker(5 * time.Second)
	defer syncTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-syncTicker.C:
			m.syncSecretsToBPF()
		default:
		}

		// Use a short deadline so we don't block forever and miss sync ticks
		m.reader.SetDeadline(time.Now().Add(1 * time.Second))
		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			// Deadline exceeded is expected — just loop back to check sync ticker
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			m.log.Error(err, "reading from ringbuf")
			continue
		}

		var event tlsEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			m.log.Error(err, "failed to parse ringbuf event")
			continue
		}

		// The rewrite is handled in-kernel! We only print events for observation.
		if event.IsRewritten == 1 {
			m.log.Info("REWRITE SUCCESS: eBPF synchronously rewrote a secret", "pid", event.Pid)
		} else {
			m.log.V(2).Info("Intercepted TLS packet (no rewrite)", "pid", event.Pid, "len", event.Len)
		}
	}
}

// syncSecretsToBPF updates the eBPF map with the latest shadow secret values
// and the watched_hosts map with hostnames from secret entries.
// Called on init and periodically. Delegates to the extracted syncSecrets function.
func (m *TLSUprobeManager) syncSecretsToBPF() {
	if err := syncSecrets(m.objs.SecretMap, m.objs.WatchedHosts, m.store, m.log); err != nil {
		m.log.Error(err, "failed to sync secrets to BPF map")
	}
}
