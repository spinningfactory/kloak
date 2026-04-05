package e2e

import (
	"strings"
	"testing"
	"time"
)

func TestMetrics_PrometheusEndpoint(t *testing.T) {
	// Create a secret so the secret reconciler fires and increments counters
	secretData := map[string][]byte{
		"api-key": []byte("my-secret-api-key-12345678"),
	}
	createEnabledSecret(t, "metrics-test-secret", secretData, nil)

	// Wait for shadow secret to be created (proves reconciler ran)
	assertShadowSecret(t, "metrics-test-secret", secretData)

	// Port-forward the controller's metrics endpoint
	url, cleanup := portForwardPod(t, kloakNamespace, "app.kubernetes.io/component=controller", 18080, 8080)
	defer cleanup()

	body := scrapeMetrics(t, url)

	// Verify kloak metrics are present in Prometheus format.
	// Only assert metrics that are guaranteed to have non-zero values:
	// - secret_sync_total fires on startup and every 5s
	// - secret_reconcile_total fires when our test secret is processed
	// - bpf_map_entries/ebpf_debug_counter are async gauges (always emitted)
	requiredMetrics := []string{
		"kloak_secret_sync_total",
		"kloak_secret_reconcile_total",
	}
	for _, metric := range requiredMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("expected metric %q not found in /metrics output", metric)
		}
	}

	// Verify standard Prometheus metadata
	if !strings.Contains(body, "# HELP kloak_") {
		t.Error("expected # HELP lines for kloak_ metrics")
	}
	if !strings.Contains(body, "# TYPE kloak_") {
		t.Error("expected # TYPE lines for kloak_ metrics")
	}

	// If eBPF is enabled, check for eBPF-specific gauges
	if strings.Contains(body, "kloak_ebpf_debug_counter") {
		t.Log("eBPF debug counters present")
	}
	if strings.Contains(body, "kloak_bpf_map_entries") {
		t.Log("BPF map entry gauges present")
	}

	t.Logf("Prometheus scrape OK: found %d kloak_ metric lines",
		strings.Count(body, "\nkloak_"))
}

func TestMetrics_OTLPPush(t *testing.T) {
	// Create a secret to trigger reconcile counters that will be pushed via OTLP
	secretData := map[string][]byte{
		"token": []byte("otlp-test-token-value-1234"),
	}
	createEnabledSecret(t, "otlp-test-secret", secretData, nil)

	// Wait for the shadow secret to confirm the controller processed it
	assertShadowSecret(t, "otlp-test-secret", secretData)

	// Wait for the OTLP periodic reader to flush (configured to 10s interval).
	t.Log("Waiting for OTLP push to collector...")
	time.Sleep(20 * time.Second)

	// Read collector logs to verify it received kloak metrics
	logs, err := kubectl("logs", "-n", kloakNamespace, "-l", "app=otel-collector", "--tail=500")
	if err != nil {
		t.Fatalf("failed to read collector logs: %v", err)
	}

	// The debug exporter logs metric names as "-> Name: kloak_..."
	if !strings.Contains(logs, "kloak_") {
		t.Logf("Collector logs (last 200 lines):\n%s", logs)
		t.Fatal("OTel Collector did not receive any kloak_ metrics via OTLP push")
	}

	// Check for specific metrics in the debug output (format: "-> Name: <metric>")
	expectedInLogs := []string{
		"kloak_secret_sync_total",
	}
	for _, metric := range expectedInLogs {
		if !strings.Contains(logs, metric) {
			t.Errorf("expected metric %q not found in collector logs", metric)
		}
	}

	t.Log("OTLP push verified: collector received kloak_ metrics")
}

func TestMetrics_ClickHouseExport(t *testing.T) {
	// Create a secret to generate metrics that flow through the pipeline
	secretData := map[string][]byte{
		"db-password": []byte("clickhouse-test-secret-val"),
	}
	createEnabledSecret(t, "ch-test-secret", secretData, nil)
	assertShadowSecret(t, "ch-test-secret", secretData)

	// Wait for: reconciler -> OTel SDK -> PeriodicReader (10s) -> Collector -> batch (5s) -> ClickHouse
	t.Log("Waiting for metrics to flow through pipeline to ClickHouse...")
	time.Sleep(25 * time.Second)

	// Port-forward to ClickHouse HTTP interface
	chURL, cleanup := portForwardPod(t, kloakNamespace, "app=clickhouse", 18123, 8123)
	defer cleanup()

	// Verify the otel database and tables were created by the exporter
	tables := queryClickHouse(t, chURL, "SHOW TABLES FROM otel")
	t.Logf("ClickHouse otel tables:\n%s", tables)

	if !strings.Contains(tables, "otel_metrics_sum") {
		t.Fatal("otel_metrics_sum table not found -- exporter didn't create schema")
	}
	if !strings.Contains(tables, "otel_metrics_gauge") {
		t.Fatal("otel_metrics_gauge table not found")
	}

	// Query counter metrics (Sum type) -- these should have kloak_ data
	sumMetrics := queryClickHouse(t, chURL,
		"SELECT DISTINCT MetricName FROM otel.otel_metrics_sum WHERE MetricName LIKE 'kloak_%' ORDER BY MetricName")
	t.Logf("ClickHouse kloak sum metrics:\n%s", sumMetrics)

	expectedSumMetrics := []string{
		"kloak_secret_sync_total",
		"kloak_secret_reconcile_total",
	}
	for _, m := range expectedSumMetrics {
		if !strings.Contains(sumMetrics, m) {
			t.Errorf("expected metric %q not found in ClickHouse otel_metrics_sum", m)
		}
	}

	// Query gauge metrics -- eBPF debug counters and BPF map sizes
	gaugeMetrics := queryClickHouse(t, chURL,
		"SELECT DISTINCT MetricName FROM otel.otel_metrics_gauge WHERE MetricName LIKE 'kloak_%' ORDER BY MetricName")
	t.Logf("ClickHouse kloak gauge metrics:\n%s", gaugeMetrics)

	expectedGaugeMetrics := []string{
		"kloak_ebpf_debug_counter",
		"kloak_bpf_map_entries",
	}
	for _, m := range expectedGaugeMetrics {
		if !strings.Contains(gaugeMetrics, m) {
			t.Errorf("expected metric %q not found in ClickHouse otel_metrics_gauge", m)
		}
	}

	// Verify actual data points exist with values
	count := queryClickHouse(t, chURL,
		"SELECT count() FROM otel.otel_metrics_sum WHERE MetricName LIKE 'kloak_%'")
	t.Logf("Total kloak sum data points in ClickHouse: %s", strings.TrimSpace(count))

	if strings.TrimSpace(count) == "0" {
		t.Error("no kloak_ data points found in ClickHouse")
	}

	t.Log("ClickHouse export verified: kloak_ metrics stored in otel database")
}
