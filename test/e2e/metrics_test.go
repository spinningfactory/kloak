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
