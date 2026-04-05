// Package metrics provides OpenTelemetry metric instruments for Kloak.
package metrics

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// BPFQuerier provides read access to live eBPF state.
// TLSUprobeManager implements this interface.
type BPFQuerier interface {
	// DebugCounterSum returns the per-CPU summed value for the named counter.
	DebugCounterSum(name string) uint64

	// MapSize returns the number of entries in the named BPF map.
	// Valid names: "secret_map", "tracked_tgids", "tracked_cgroups", "dns_ip_map".
	MapSize(name string) int
}

// bpfQuerierRef is a thread-safe, late-binding wrapper around BPFQuerier.
// Async OTel callbacks close over this so we can set the real querier
// after the uprobe manager is constructed.
type bpfQuerierRef struct {
	mu  sync.RWMutex
	val BPFQuerier
}

func (r *bpfQuerierRef) set(q BPFQuerier) {
	r.mu.Lock()
	r.val = q
	r.mu.Unlock()
}

func (r *bpfQuerierRef) get() BPFQuerier {
	r.mu.RLock()
	q := r.val
	r.mu.RUnlock()
	return q
}

// DebugCounterNames lists all eBPF debug counter names (must match C enum order).
var DebugCounterNames = []string{
	"kprobe_entry", "kprobe_tracked", "kprobe_dport53", "kprobe_dport0",
	"kprobe_dport_other", "kprobe_iov_ok", "kretprobe_entry", "kretprobe_ret_small",
	"kretprobe_read_fail", "kretprobe_read_ok", "dns_parse_entry", "dns_not_response",
	"dns_no_answers", "dns_qname_fail", "dns_not_watched", "dns_watched_hit",
	"dns_answer_stored", "phase2_entered",
	"resolve_ssl_fd_hit", "resolve_last_vfd_hit", "resolve_fd_scan_hit",
	"resolve_no_fd", "resolve_no_conn", "resolve_no_dns", "resolve_host_ok",
}

// BPFMapNames lists the BPF maps whose sizes are tracked as gauges.
var BPFMapNames = []string{"secret_map", "tracked_tgids", "tracked_cgroups", "dns_ip_map"}

// Metrics holds all OTel metric instruments for Kloak.
// A nil *Metrics is safe to call — all recording methods are no-ops.
type Metrics struct {
	tlsWriteTotal        metric.Int64Counter
	tlsRewriteTotal      metric.Int64Counter
	uprobeAttachTotal    metric.Int64Counter
	secretSyncTotal      metric.Int64Counter
	podReconcileTotal    metric.Int64Counter
	secretReconcileTotal metric.Int64Counter

	tlsWriteBytes metric.Int64Histogram

	bpfRef *bpfQuerierRef
}

// New creates a Metrics instance and registers all instruments on the given meter.
// bpf may be nil; use SetBPFQuerier to wire it later.
func New(meter metric.Meter, bpf BPFQuerier) (*Metrics, error) {
	ref := &bpfQuerierRef{}
	if bpf != nil {
		ref.set(bpf)
	}

	m := &Metrics{bpfRef: ref}
	var err error

	if m.tlsWriteTotal, err = meter.Int64Counter("kloak_tls_write_total",
		metric.WithDescription("Total TLS write events intercepted")); err != nil {
		return nil, err
	}
	if m.tlsRewriteTotal, err = meter.Int64Counter("kloak_tls_rewrite_total",
		metric.WithDescription("Total TLS writes where a secret was rewritten")); err != nil {
		return nil, err
	}
	if m.uprobeAttachTotal, err = meter.Int64Counter("kloak_uprobe_attach_total",
		metric.WithDescription("Total uprobe attach attempts")); err != nil {
		return nil, err
	}
	if m.secretSyncTotal, err = meter.Int64Counter("kloak_secret_sync_total",
		metric.WithDescription("Total secret-to-BPF sync cycles")); err != nil {
		return nil, err
	}
	if m.podReconcileTotal, err = meter.Int64Counter("kloak_pod_reconcile_total",
		metric.WithDescription("Total pod reconcile cycles")); err != nil {
		return nil, err
	}
	if m.secretReconcileTotal, err = meter.Int64Counter("kloak_secret_reconcile_total",
		metric.WithDescription("Total secret reconcile cycles")); err != nil {
		return nil, err
	}
	if m.tlsWriteBytes, err = meter.Int64Histogram("kloak_tls_write_bytes",
		metric.WithDescription("Size distribution of intercepted TLS writes in bytes")); err != nil {
		return nil, err
	}

	// Register async gauge for eBPF debug counters.
	debugGauge, err := meter.Int64ObservableGauge("kloak_ebpf_debug_counter",
		metric.WithDescription("eBPF debug counter values (cumulative per-CPU sums)"))
	if err != nil {
		return nil, err
	}

	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		q := ref.get()
		if q == nil {
			return nil
		}
		for _, name := range DebugCounterNames {
			o.ObserveInt64(debugGauge, int64(q.DebugCounterSum(name)),
				metric.WithAttributes(attribute.String("counter", name)),
			)
		}
		return nil
	}, debugGauge)
	if err != nil {
		return nil, err
	}

	// Register async gauge for BPF map sizes.
	mapGauge, err := meter.Int64ObservableGauge("kloak_bpf_map_entries",
		metric.WithDescription("Number of entries in eBPF maps"))
	if err != nil {
		return nil, err
	}

	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		q := ref.get()
		if q == nil {
			return nil
		}
		for _, name := range BPFMapNames {
			o.ObserveInt64(mapGauge, int64(q.MapSize(name)),
				metric.WithAttributes(attribute.String("map", name)),
			)
		}
		return nil
	}, mapGauge)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// SetBPFQuerier sets the BPF querier for async gauge callbacks.
// Call this after the TLSUprobeManager is constructed.
func (m *Metrics) SetBPFQuerier(q BPFQuerier) {
	if m == nil {
		return
	}
	m.bpfRef.set(q)
}

// RecordTLSWrite records one TLS write event.
func (m *Metrics) RecordTLSWrite(length uint32, isRewritten bool) {
	if m == nil {
		return
	}
	m.tlsWriteTotal.Add(context.Background(), 1)
	m.tlsWriteBytes.Record(context.Background(), int64(length))
	if isRewritten {
		m.tlsRewriteTotal.Add(context.Background(), 1)
	}
}

// RecordUprobeAttach records an uprobe attach attempt.
func (m *Metrics) RecordUprobeAttach(success bool) {
	if m == nil {
		return
	}
	result := "success"
	if !success {
		result = "failure"
	}
	m.uprobeAttachTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("result", result),
	))
}

// RecordSecretSync records one syncSecretsToBPF cycle.
func (m *Metrics) RecordSecretSync() {
	if m == nil {
		return
	}
	m.secretSyncTotal.Add(context.Background(), 1)
}

// RecordPodReconcile records one pod reconcile cycle.
// outcome should be "ok", "requeue", or "error".
func (m *Metrics) RecordPodReconcile(outcome string) {
	if m == nil {
		return
	}
	m.podReconcileTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("result", outcome),
	))
}

// RecordSecretReconcile records one secret reconcile cycle.
// outcome should be "ok", "requeue", or "error".
func (m *Metrics) RecordSecretReconcile(outcome string) {
	if m == nil {
		return
	}
	m.secretReconcileTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("result", outcome),
	))
}
