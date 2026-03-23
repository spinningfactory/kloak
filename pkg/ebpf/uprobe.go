package ebpf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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

// dnsIPKey matches C struct dns_ip_key used in dns_ip_map.
// Key: {tgid, _pad=0, ip[16]} — IPv4 stored as ::ffff:a.b.c.d.
type dnsIPKey struct {
	Tgid uint32
	_    uint32 // padding to align IP to 8-byte boundary, must match C struct dns_ip_key
	IP   [16]byte
}

// dnsIPVal matches C struct dns_ip_val.
type dnsIPVal struct {
	Hostname    [32]byte
	HostLen     uint32
	TTLSec      uint32
	InsertedKNs uint64
}

// connIPKey matches C struct conn_ip_key used in conn_ip_map.
type connIPKey struct {
	Tgid uint32
	Fd   uint32
}

// sslFdKey matches C struct ssl_fd_key used in ssl_fd_map.
type sslFdKey struct {
	Tgid   uint32
	_      uint32 // padding to align SslPtr to 8-byte boundary, must match C struct ssl_fd_key
	SslPtr uint64
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

	// dnsConfigured is true once we've written at least one DNS server IP to
	// the dns_config BPF map. We only need to do this once per node since all
	// Kubernetes pods use the same cluster DNS server.
	dnsConfigured bool
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

	// Attach node-wide tracepoints for DNS response and TCP connect tracking.
	// These are global hooks filtered by tracked_tgids in the BPF programs.
	tpSpecs := []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"syscalls", "sys_enter_recvfrom", objs.TpEnterRecvfrom},
		{"syscalls", "sys_exit_recvfrom", objs.TpExitRecvfrom},
		{"syscalls", "sys_enter_connect", objs.TpEnterConnect},
		{"syscalls", "sys_exit_connect", objs.TpExitConnect},
	}

	var tpLinks []link.Link
	for _, tp := range tpSpecs {
		l, tpErr := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if tpErr != nil {
			log.Error(tpErr, "failed to attach tracepoint (DNS/connect tracking disabled)",
				"tracepoint", tp.group+"/"+tp.name)
			// Non-fatal: fall back to SNI-only host verification
			break
		}
		tpLinks = append(tpLinks, l)
	}

	links := make([]link.Link, 0, len(tpLinks))
	links = append(links, tpLinks...)

	return &TLSUprobeManager{
		objs:   objs,
		reader: reader,
		log:    log,
		store:  store,
		links:  links,
	}, nil
}

// AttachTLS attempts to automatically detect the runtime language and attach
// the correct eBPF uprobes (Go crypto/tls or OpenSSL) to the given PID.
func (m *TLSUprobeManager) AttachTLS(pid int) error {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

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
	// SNI hostname capture — called once per connection before handshake.
	// Populates the conn_hosts BPF map for protocol-agnostic host filtering.
	// SSL_set_tlsext_host_name is a real function in BoringSSL but a macro in
	// OpenSSL that expands to SSL_ctrl(ssl, 55, 0, name). Try both.
	sniSymbols := []string{"SSL_set_tlsext_host_name"}
	sniCtrlSymbols := []string{"SSL_ctrl"}
	// SSL_set_fd links the SSL object to a socket fd, enabling the IP-verified
	// host resolution chain: ssl_ptr → fd → peer IP → DNS hostname.
	sslSetFdSymbols := []string{"SSL_set_fd"}
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
	for _, sym := range sniSymbols {
		up, err := ex.Uprobe(sym, m.objs.BpfUprobeSslSetHost, nil)
		if err == nil {
			m.log.Info("Attached SNI uprobe to main exe", "pid", pid, "symbol", sym)
			m.links = append(m.links, up)
		}
	}
	for _, sym := range sniCtrlSymbols {
		up, err := ex.Uprobe(sym, m.objs.BpfUprobeSslCtrl, nil)
		if err == nil {
			m.log.Info("Attached SNI ctrl uprobe to main exe", "pid", pid, "symbol", sym)
			m.links = append(m.links, up)
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
		for _, sym := range sniSymbols {
			up, err := libEx.Uprobe(sym, m.objs.BpfUprobeSslSetHost, nil)
			if err == nil {
				m.log.Info("Attached SNI uprobe to shared library", "pid", pid, "symbol", sym, "lib", libPath)
				m.links = append(m.links, up)
			}
		}
		for _, sym := range sniCtrlSymbols {
			up, err := libEx.Uprobe(sym, m.objs.BpfUprobeSslCtrl, nil)
			if err == nil {
				m.log.Info("Attached SNI ctrl uprobe to shared library", "pid", pid, "symbol", sym, "lib", libPath)
				m.links = append(m.links, up)
			}
		}
		for _, sym := range sslSetFdSymbols {
			up, err := libEx.Uprobe(sym, m.objs.BpfUprobeSslSetFd, nil)
			if err == nil {
				m.log.Info("Attached SSL_set_fd uprobe to shared library", "pid", pid, "symbol", sym, "lib", libPath)
				m.links = append(m.links, up)
			}
		}
	}

	// Also try SSL_set_fd on main executable (statically linked OpenSSL/BoringSSL)
	for _, sym := range sslSetFdSymbols {
		up, err := ex.Uprobe(sym, m.objs.BpfUprobeSslSetFd, nil)
		if err == nil {
			m.log.Info("Attached SSL_set_fd uprobe to main exe", "pid", pid, "symbol", sym)
			m.links = append(m.links, up)
		}
	}

	if !attached {
		return fmt.Errorf("could not find compatible TLS symbols for PID %d", pid)
	}

	// Mark this process group as monitored so DNS/connect tracepoints process it.
	// In Kubernetes, cgroup.procs lists TGIDs (process group leaders) so pid == tgid.
	tgid := uint32(pid)
	if err := m.TrackTGID(tgid); err != nil {
		m.log.Error(err, "failed to track TGID in BPF map", "tgid", tgid)
	}

	// Configure DNS server IP once per node (all Kubernetes pods share the same CoreDNS ClusterIP).
	if !m.dnsConfigured {
		dnsIPs := readDNSServersFromResolvConf(pid)
		for i, ip := range dnsIPs {
			if err := m.SetDNSServer(ip, uint32(i)); err != nil {
				m.log.Error(err, "failed to set DNS server in BPF map", "ip", ip)
			} else {
				m.log.Info("Configured DNS server for interception", "ip", ip, "idx", i)
				m.dnsConfigured = true
			}
		}
		if !m.dnsConfigured {
			m.log.Info("Could not read DNS server from resolv.conf — DNS-based host verification will be inactive", "pid", pid)
		}
	}

	return nil
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

// TrackTGID marks a process group (tgid) as monitored in the tracked_tgids BPF
// map so that node-wide tracepoints (DNS, connect) only process its syscalls.
// Called from AttachTLS after a successful uprobe attachment.
func (m *TLSUprobeManager) TrackTGID(tgid uint32) error {
	val := uint8(1)
	return m.objs.TrackedTgids.Put(tgid, val)
}

// UntrackTGID removes a process group from the tracked_tgids BPF map.
// Best-effort: errors are logged but not propagated, since the process is
// typically already dead (pod deletion) and LRU eviction handles overflow.
func (m *TLSUprobeManager) UntrackTGID(tgid uint32) {
	if err := m.objs.TrackedTgids.Delete(tgid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		m.log.V(1).Info("failed to untrack TGID", "tgid", tgid, "err", err)
	}
}

// SetDNSServer stores a DNS server IP in the dns_config BPF map.
// The map holds up to 4 entries (for resolv.conf with multiple nameservers).
// idx 0 is always the primary server; subsequent calls add alternates.
func (m *TLSUprobeManager) SetDNSServer(ip net.IP, idx uint32) error {
	if idx >= 4 {
		return nil // silently ignore extra entries
	}
	v16 := ip.To16()
	if v16 == nil {
		return fmt.Errorf("invalid IP: %v", ip)
	}
	var val [16]byte
	copy(val[:], v16)
	return m.objs.DnsConfig.Put(idx, val)
}

// readDNSServersFromResolvConf reads nameserver lines from a container's
// /etc/resolv.conf via the process's mount namespace (/proc/<pid>/root).
// Returns up to 4 IP addresses.
func readDNSServersFromResolvConf(pid int) []net.IP {
	path := fmt.Sprintf("/proc/%d/root/etc/resolv.conf", pid)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck // read-only file, close error is inconsequential

	var ips []net.IP
	scanner := bufio.NewScanner(f)
	for scanner.Scan() && len(ips) < 4 {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
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

// syncSecretsToBPF updates the eBPF map with the latest shadow secret values.
// Called on init and periodically. Delegates to the extracted syncSecrets function.
func (m *TLSUprobeManager) syncSecretsToBPF() {
	if err := syncSecrets(m.objs.SecretMap, m.store, m.log); err != nil {
		m.log.Error(err, "failed to sync secrets to BPF map")
	}
}
