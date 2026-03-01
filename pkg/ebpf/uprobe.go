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
	"github.com/spinningfactory/kloak/pkg/storage"
	ctrl "sigs.k8s.io/controller-runtime"
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
	AllowedHost [64]byte
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_arm64" tlsuprobe bpf/tls_uprobe.c -- -I../ebpf

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
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction | ebpf.LogLevelBranch,
		},
	}
	if err := loadTlsuprobeObjects(objs, opts); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.TlsEvents)
	if err != nil {
		objs.Close()
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
	// OpenSSL functions might be in libssl.so, which we would have to search for in /proc/pid/maps,
	// or statically linked into the main binary.
	// For simplicity in this demo, let's try attaching to SSL_write on the main executable.
	// In a complete implementation, we'd parse /proc/pid/maps to find the absolute path of libssl.so.
	sslWriteSym := "SSL_write"
	upSSL, err := ex.Uprobe(sslWriteSym, m.objs.BpfUprobeSslWrite, nil)
	if err == nil {
		m.log.Info("Attached OpenSSL uprobe to process", "pid", pid, "symbol", sslWriteSym)
		m.links = append(m.links, upSSL)
		return nil
	} else if !errors.Is(err, link.ErrNoSymbol) && !strings.Contains(err.Error(), "no symbol") {
		m.log.V(1).Info("failed to attach OpenSSL uprobe to main exe", "error", err)
	}

	// TODO: Parse /proc/<pid>/maps for "libssl.so" and link.OpenExecutable() on that library.
	libsslPath, err := findLibSSL(pid)
	if err == nil && libsslPath != "" {
		libEx, err := link.OpenExecutable(libsslPath)
		if err == nil {
			upLibSSL, err := libEx.Uprobe(sslWriteSym, m.objs.BpfUprobeSslWrite, nil)
			if err == nil {
				m.log.Info("Attached OpenSSL uprobe to shared library", "pid", pid, "lib", libsslPath)
				m.links = append(m.links, upLibSSL)
				return nil
			}
		}
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
		m.reader.Close()
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
// Called on init and periodically or when triggered.
func (m *TLSUprobeManager) syncSecretsToBPF(ctx context.Context) {
	secrets, err := m.store.List(ctx)
	if err != nil {
		m.log.Error(err, "failed to list secrets to sync to BPF map")
		return
	}

	for hash, entry := range secrets {
		// hash is already the full shadow value like "kloak:0a6dbc80-b38a-47"
		shadowPrefix := hash

		// Adjust length to match exactly, as the secret_reconciler does
		if len(shadowPrefix) > len(entry.Value) {
			shadowPrefix = shadowPrefix[:len(entry.Value)]
		} else if len(shadowPrefix) < len(entry.Value) {
			shadowPrefix = shadowPrefix + strings.Repeat(" ", len(entry.Value)-len(shadowPrefix))
		}

		// The BPF program looks up the first 16 bytes of the shadow secret
		if len(shadowPrefix) < 16 {
			// Skip too short secrets for now (needs to be padded or managed differently)
			m.log.V(1).Info("Skipping secret too short for 16-byte BPF key", "hash", hash)
			continue
		}

		var key secretKey
		copy(key.Prefix[:], []byte(shadowPrefix)[:16])

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
			if len(host) > 64 {
				host = host[:64]
			}
			val.HostLen = uint32(len(host))
			copy(val.AllowedHost[:], []byte(host))
		}
		// HostLen == 0 means wildcard (allow all hosts)

		// Save into eBPF Map
		if err := m.objs.SecretMap.Update(&key, &val, 0); err != nil {
			m.log.Error(err, "failed to update BPF secret_map", "hash", hash)
		} else {
			m.log.Info("Synced secret into eBPF map", "hash", hash, "hostLen", val.HostLen)
		}
	}
}
