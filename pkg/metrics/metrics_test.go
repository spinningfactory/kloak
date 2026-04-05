package metrics_test

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	kloakmetrics "github.com/spinningfactory/kloak/pkg/metrics"
)

// stubBPFQuerier implements BPFQuerier for testing without eBPF.
type stubBPFQuerier struct {
	counters map[string]uint64
	maps     map[string]int
}

func (s *stubBPFQuerier) DebugCounterSum(name string) uint64 { return s.counters[name] }
func (s *stubBPFQuerier) MapSize(name string) int            { return s.maps[name] }

// newTestMetrics creates a Metrics instance with an in-memory reader for assertions.
func newTestMetrics(t *testing.T, bpf kloakmetrics.BPFQuerier) (*kloakmetrics.Metrics, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	meter := provider.Meter("kloak.test")
	m, err := kloakmetrics.New(meter, bpf)
	if err != nil {
		t.Fatalf("metrics.New: %v", err)
	}
	return m, reader
}

func collect(t *testing.T, reader *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return rm
}

// findCounterSum finds the sum of a named Int64Counter, optionally filtered by attributes.
func findCounterSum(t *testing.T, rm metricdata.ResourceMetrics, name string, attrs ...attribute.KeyValue) int64 {
	t.Helper()
	set := attribute.NewSet(attrs...)
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %s is not Sum[int64]", name)
			}
			var total int64
			for _, dp := range sum.DataPoints {
				if len(attrs) == 0 || dp.Attributes.Equals(&set) {
					total += dp.Value
				}
			}
			return total
		}
	}
	return 0
}

// findHistogramCount finds the count of a named Int64Histogram.
func findHistogramCount(t *testing.T, rm metricdata.ResourceMetrics, name string) uint64 {
	t.Helper()
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			hist, ok := m.Data.(metricdata.Histogram[int64])
			if !ok {
				t.Fatalf("metric %s is not Histogram[int64]", name)
			}
			var total uint64
			for _, dp := range hist.DataPoints {
				total += dp.Count
			}
			return total
		}
	}
	return 0
}

// findHistogramSum finds the sum of a named Int64Histogram.
func findHistogramSum(t *testing.T, rm metricdata.ResourceMetrics, name string) int64 {
	t.Helper()
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			hist, ok := m.Data.(metricdata.Histogram[int64])
			if !ok {
				t.Fatalf("metric %s is not Histogram[int64]", name)
			}
			var total int64
			for _, dp := range hist.DataPoints {
				total += dp.Sum
			}
			return total
		}
	}
	return 0
}

// findGaugeValue finds the value of a named Int64ObservableGauge with matching attributes.
func findGaugeValue(t *testing.T, rm metricdata.ResourceMetrics, name string, attrs ...attribute.KeyValue) int64 {
	t.Helper()
	set := attribute.NewSet(attrs...)
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			gauge, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				t.Fatalf("metric %s is not Gauge[int64]", name)
			}
			for _, dp := range gauge.DataPoints {
				if dp.Attributes.Equals(&set) {
					return dp.Value
				}
			}
		}
	}
	return 0
}

func TestMetrics_TLSWrite_NoRewrite(t *testing.T) {
	m, reader := newTestMetrics(t, nil)

	m.RecordTLSWrite(100, false, kloakmetrics.TLSWriteContext{})
	m.RecordTLSWrite(200, false, kloakmetrics.TLSWriteContext{})
	m.RecordTLSWrite(50, false, kloakmetrics.TLSWriteContext{})

	rm := collect(t, reader)

	if got := findCounterSum(t, rm, "kloak_tls_write_total"); got != 3 {
		t.Errorf("kloak_tls_write_total = %d, want 3", got)
	}
	if got := findCounterSum(t, rm, "kloak_tls_rewrite_total"); got != 0 {
		t.Errorf("kloak_tls_rewrite_total = %d, want 0", got)
	}
	if got := findHistogramCount(t, rm, "kloak_tls_write_bytes"); got != 3 {
		t.Errorf("kloak_tls_write_bytes count = %d, want 3", got)
	}
	if got := findHistogramSum(t, rm, "kloak_tls_write_bytes"); got != 350 {
		t.Errorf("kloak_tls_write_bytes sum = %d, want 350", got)
	}
}

func TestMetrics_TLSWrite_WithRewrite(t *testing.T) {
	m, reader := newTestMetrics(t, nil)

	m.RecordTLSWrite(50, true, kloakmetrics.TLSWriteContext{})
	m.RecordTLSWrite(50, true, kloakmetrics.TLSWriteContext{})
	m.RecordTLSWrite(50, false, kloakmetrics.TLSWriteContext{})

	rm := collect(t, reader)

	if got := findCounterSum(t, rm, "kloak_tls_write_total"); got != 3 {
		t.Errorf("kloak_tls_write_total = %d, want 3", got)
	}
	if got := findCounterSum(t, rm, "kloak_tls_rewrite_total"); got != 2 {
		t.Errorf("kloak_tls_rewrite_total = %d, want 2", got)
	}
}

func TestMetrics_UprobeAttach_SuccessAndFailure(t *testing.T) {
	m, reader := newTestMetrics(t, nil)

	m.RecordUprobeAttach(true)
	m.RecordUprobeAttach(true)
	m.RecordUprobeAttach(false)

	rm := collect(t, reader)

	if got := findCounterSum(t, rm, "kloak_uprobe_attach_total",
		attribute.String("result", "success")); got != 2 {
		t.Errorf("uprobe_attach{result=success} = %d, want 2", got)
	}
	if got := findCounterSum(t, rm, "kloak_uprobe_attach_total",
		attribute.String("result", "failure")); got != 1 {
		t.Errorf("uprobe_attach{result=failure} = %d, want 1", got)
	}
}

func TestMetrics_SecretSync(t *testing.T) {
	m, reader := newTestMetrics(t, nil)

	for range 5 {
		m.RecordSecretSync()
	}

	rm := collect(t, reader)
	if got := findCounterSum(t, rm, "kloak_secret_sync_total"); got != 5 {
		t.Errorf("kloak_secret_sync_total = %d, want 5", got)
	}
}

func TestMetrics_PodReconcile_Outcomes(t *testing.T) {
	m, reader := newTestMetrics(t, nil)

	m.RecordPodReconcile("ok")
	m.RecordPodReconcile("ok")
	m.RecordPodReconcile("requeue")
	m.RecordPodReconcile("error")

	rm := collect(t, reader)

	tests := []struct {
		result string
		want   int64
	}{
		{"ok", 2},
		{"requeue", 1},
		{"error", 1},
	}
	for _, tt := range tests {
		if got := findCounterSum(t, rm, "kloak_pod_reconcile_total",
			attribute.String("result", tt.result)); got != tt.want {
			t.Errorf("pod_reconcile{result=%s} = %d, want %d", tt.result, got, tt.want)
		}
	}
}

func TestMetrics_SecretReconcile_Outcomes(t *testing.T) {
	m, reader := newTestMetrics(t, nil)

	m.RecordSecretReconcile("ok")
	m.RecordSecretReconcile("ok")
	m.RecordSecretReconcile("ok")
	m.RecordSecretReconcile("error")

	rm := collect(t, reader)

	if got := findCounterSum(t, rm, "kloak_secret_reconcile_total",
		attribute.String("result", "ok")); got != 3 {
		t.Errorf("secret_reconcile{result=ok} = %d, want 3", got)
	}
	if got := findCounterSum(t, rm, "kloak_secret_reconcile_total",
		attribute.String("result", "error")); got != 1 {
		t.Errorf("secret_reconcile{result=error} = %d, want 1", got)
	}
}

func TestMetrics_NilSafe(t *testing.T) {
	var m *kloakmetrics.Metrics
	// None of these should panic.
	m.RecordTLSWrite(100, true, kloakmetrics.TLSWriteContext{})
	m.RecordUprobeAttach(true)
	m.RecordSecretSync()
	m.RecordPodReconcile("ok")
	m.RecordSecretReconcile("ok")
	m.SetBPFQuerier(nil)
}

func TestMetrics_BPFQuerier_AsyncCallbacks(t *testing.T) {
	stub := &stubBPFQuerier{
		counters: map[string]uint64{
			"phase2_entered":   42,
			"dns_watched_hit":  7,
			"resolve_host_ok":  100,
		},
		maps: map[string]int{
			"secret_map":      3,
			"tracked_tgids":   5,
			"tracked_cgroups": 2,
			"dns_ip_map":      10,
		},
	}

	m, reader := newTestMetrics(t, nil)
	// Late-bind the BPF querier, as production code does.
	m.SetBPFQuerier(stub)

	rm := collect(t, reader)

	// Verify debug counters.
	if got := findGaugeValue(t, rm, "kloak_ebpf_debug_counter",
		attribute.String("counter", "phase2_entered")); got != 42 {
		t.Errorf("debug_counter{counter=phase2_entered} = %d, want 42", got)
	}
	if got := findGaugeValue(t, rm, "kloak_ebpf_debug_counter",
		attribute.String("counter", "dns_watched_hit")); got != 7 {
		t.Errorf("debug_counter{counter=dns_watched_hit} = %d, want 7", got)
	}
	if got := findGaugeValue(t, rm, "kloak_ebpf_debug_counter",
		attribute.String("counter", "resolve_host_ok")); got != 100 {
		t.Errorf("debug_counter{counter=resolve_host_ok} = %d, want 100", got)
	}

	// Verify BPF map gauges.
	if got := findGaugeValue(t, rm, "kloak_bpf_map_entries",
		attribute.String("map", "secret_map")); got != 3 {
		t.Errorf("bpf_map_entries{map=secret_map} = %d, want 3", got)
	}
	if got := findGaugeValue(t, rm, "kloak_bpf_map_entries",
		attribute.String("map", "dns_ip_map")); got != 10 {
		t.Errorf("bpf_map_entries{map=dns_ip_map} = %d, want 10", got)
	}
}
