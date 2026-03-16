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

// secretKey matches C struct secret_key
type secretKey struct {
	Prefix [16]byte
}

// secretValue matches C struct secret_value
type secretValue struct {
	Len         uint32
	RealSecret  [128]byte
	HostLen     uint32
	AllowedHost [32]byte
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
				LogLevel: ebpf.LogLevelBranch,
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

	return &TLSUprobeManager{
		objs:   objs,
		reader: reader,
		log:    log,
		store:  store,
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

	// 2. Try OpenSSL (Node.js, Python, Rust)
	// Modern OpenSSL 3.x has both SSL_write (legacy) and SSL_write_ex (preferred).
	// Python 3.11+ uses SSL_write_ex exclusively, so we must probe both.
	// The calling convention is identical for the first 3 params (ssl, buf, len).
	sslSymbols := []string{"SSL_write", "SSL_write_ex"}
	attached := false

	// Try main executable first
	for _, sym := range sslSymbols {
		up, err := ex.Uprobe(sym, m.objs.BpfUprobeSslWrite, nil)
		if err == nil {
			m.log.Info("Attached OpenSSL uprobe to main exe", "pid", pid, "symbol", sym)
			m.links = append(m.links, up)
			attached = true
		}
	}

	// Try libssl.so shared library
	libsslPath, err := findLibSSL(pid)
	if err == nil && libsslPath != "" {
		libEx, err := link.OpenExecutable(libsslPath)
		if err == nil {
			for _, sym := range sslSymbols {
				up, err := libEx.Uprobe(sym, m.objs.BpfUprobeSslWrite, nil)
				if err == nil {
					m.log.Info("Attached OpenSSL uprobe to shared library", "pid", pid, "symbol", sym, "lib", libsslPath)
					m.links = append(m.links, up)
					attached = true
				}
			}
		}
	}

	if attached {
		return nil
	}

	return fmt.Errorf("could not find compatible TLS symbols for PID %d", pid)
}

func findLibSSL(pid int) (string, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "libssl.so") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				path := parts[len(parts)-1]
				if strings.HasPrefix(path, "/") {
					// We must access the file through the root namespace or /proc/pid/root
					return fmt.Sprintf("/proc/%d/root%s", pid, path), nil
				}
			}
		}
	}
	return "", fmt.Errorf("libssl not found in maps")
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
	m.syncSecretsToBPF(ctx)

	// Periodic re-sync ticker. The initial sync may have found an empty store
	// (secret reconciler hasn't run yet), so we must keep re-syncing.
	syncTicker := time.NewTicker(5 * time.Second)
	defer syncTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-syncTicker.C:
			m.syncSecretsToBPF(ctx)
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
// Called on init and periodically. Stale entries (secrets deleted from storage)
// are removed from the map so the eBPF program stops rewriting them.
func (m *TLSUprobeManager) syncSecretsToBPF(ctx context.Context) {
	secrets, err := m.store.List(ctx)
	if err != nil {
		m.log.Error(err, "failed to list secrets to sync to BPF map")
		return
	}

	// newKeys tracks which keys we upsert so we can prune stale entries afterwards.
	newKeys := make(map[secretKey]struct{}, len(secrets))

	for hash, entry := range secrets {
		// hash is already the full shadow value like "kloak:0a6dbc80-b38a-47"
		shadowPrefix := hash

		// Adjust length to match exactly, as the secret_reconciler does
		if len(shadowPrefix) > len(entry.Value) {
			shadowPrefix = shadowPrefix[:len(entry.Value)]
		} else if len(shadowPrefix) < len(entry.Value) {
			shadowPrefix += strings.Repeat(" ", len(entry.Value)-len(shadowPrefix))
		}

		// The BPF program looks up the first 16 bytes of the shadow secret
		if len(shadowPrefix) < 16 {
			m.log.V(1).Info("Skipping secret too short for 16-byte BPF key", "hash", hash)
			continue
		}

		var key secretKey
		copy(key.Prefix[:], []byte(shadowPrefix)[:16])
		newKeys[key] = struct{}{}

		var val secretValue
		val.Len = uint32(len(entry.Value))
		if val.Len > 128 {
			m.log.V(1).Info("Truncating secret value to max BPF size (128)", "hash", hash)
			val.Len = 128
		}
		copy(val.RealSecret[:], []byte(entry.Value)[:val.Len])

		// Set allowed host for host-based filtering
		if len(entry.AllowedHosts) > 0 && entry.AllowedHosts[0] != "*" {
			host := entry.AllowedHosts[0]
			if len(host) > 32 {
				host = host[:32]
			}
			val.HostLen = uint32(len(host))
			copy(val.AllowedHost[:], host)
		}
		// HostLen == 0 means wildcard (allow all hosts)

		if err := m.objs.SecretMap.Update(&key, &val, 0); err != nil {
			m.log.Error(err, "failed to update BPF secret_map", "hash", hash)
		} else {
			m.log.Info("Synced secret into eBPF map", "hash", hash, "hostLen", val.HostLen)
		}
	}

	// Prune stale entries: iterate existing map keys and delete any not in newKeys.
	var staleKeys []secretKey
	var iterKey secretKey
	var iterVal secretValue
	iter := m.objs.SecretMap.Iterate()
	for iter.Next(&iterKey, &iterVal) {
		if _, exists := newKeys[iterKey]; !exists {
			staleKeys = append(staleKeys, iterKey)
		}
	}
	if err := iter.Err(); err != nil {
		m.log.Error(err, "error iterating BPF secret_map for pruning")
	}
	for i := range staleKeys {
		if err := m.objs.SecretMap.Delete(&staleKeys[i]); err != nil {
			m.log.Error(err, "failed to delete stale BPF secret_map entry")
		} else {
			m.log.Info("Pruned stale entry from eBPF map")
		}
	}
}
