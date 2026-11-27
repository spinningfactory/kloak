package ebpf

// The data plane's event counters as Prometheus metrics.
//
// The BPF programs count what they do in debug_counters (bpf/tls_uprobe.c,
// the DBG_* enum), a per-CPU array, always compiled in: the placeholders
// they rewrite, and every reason one goes out without its real value. The
// controller exports them, summed over CPUs, as
//
//	kloak_dataplane_events_total{event="<name>", class="<class>"}
//
// read from the map at scrape time (dataplaneCollector), so that nothing
// polls it in between. The class says what an event means to an operator
// (eventClass): alert on class "unrewritten", "dropped" and "refused" (see
// the README, Metrics).
//
// debug_counters is pinned with the rest of the data plane (pins.go): a
// controller that adopts it carries on from its values, so the counters
// carry on across the restart. One that loads the data plane again starts
// them at 0, which Prometheus takes as a counter reset (a new process).
// Within one process, the totals never go backwards: a new source (another
// data plane) adds to them, and a value that goes down is taken as a reset.

import (
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// eventClass is what a data-plane event means to an operator.
type eventClass string

const (
	// eventUnrewritten: a placeholder the data plane found went out without
	// its real value, because of a failure or a limit (it fails closed):
	// the request carrying it fails upstream.
	eventUnrewritten eventClass = "unrewritten"
	// eventRefused: a rewrite the policy refused (the pod's secret
	// binding, the SNI check, the secret's host, IP or port), or a connect
	// to a virtual IP refused. Expected for a misbehaving or misconfigured
	// workload; a sudden rise is worth a look.
	eventRefused eventClass = "refused"
	// eventDropped: a packet or segment the data plane dropped. None does
	// today. TODO(kloak#383): the tc ledger (phase 2) classes its drops so.
	eventDropped eventClass = "dropped"
	// eventAudit: a rewrite an audit mode let through, which enforce would
	// have refused (--secret-binding, --sni-check).
	eventAudit eventClass = "audit"
	// eventInfo: the data plane's normal work, and diagnostics of its steps.
	eventInfo eventClass = "info"
)

// alertClasses are the classes the README's sample alerts select.
var alertClasses = []eventClass{eventUnrewritten, eventDropped, eventRefused}

// dataplaneEvent is one debug_counters index.
type dataplaneEvent struct {
	name  string // the DBG_* constant, lowercased, without DBG_
	class eventClass
}

// dataplaneEvents are debug_counters' indexes, in the order of the DBG_*
// enum in bpf/tls_uprobe.c: entry i is index i. A counter added to the enum
// needs its entry here, at its position, with its class:
// TestDataplaneEventsMatchEnum fails until it has one.
var dataplaneEvents = []dataplaneEvent{
	{"xor_conn_check", eventInfo},
	{"xor_conn_hit", eventInfo},
	{"xor_prescan_match", eventInfo},
	{"xor_prescan_unconfirmed", eventInfo},
	{"xor_tailcall", eventInfo},
	{"xor_path_entered", eventInfo},
	{"xor_secret_found", eventInfo},
	{"xor_delta_done", eventInfo},
	{"tc_entry", eventInfo},
	{"tc_match", eventInfo},
	{"tc_patched", eventInfo},
	{"kprobe_bridge", eventInfo},
	{"kprobe_bridge_no_entry", eventInfo},
	// No H for the connection: its staged patches are dropped, and the
	// write's placeholders go out as they are.
	{"kprobe_bridge_h_fail", eventUnrewritten},
	{"evp_init_entry", eventInfo},
	{"evp_init_h_ok", eventInfo},
	{"evp_init_h_zero", eventInfo},
	{"evp_init_chain_fail", eventInfo},
	{"h_extract_cache_hit", eventInfo},
	{"h_extract_cache_miss", eventInfo},
	{"kprobe_bridge_from_pending", eventInfo},
	{"kprobe_walk_legacy", eventInfo},
	{"h_extract_live_walk", eventInfo},
	{"bssl_reached", eventInfo},
	{"bssl_h_ok", eventInfo},
	{"bssl_s3_null", eventInfo},
	{"bssl_aead_null", eventInfo},
	{"bssl_rdkey_fail", eventInfo},
	{"bssl_rounds_bad", eventInfo},
	{"bssl_hzero", eventInfo},
	{"ossl_gcm_gate_fail", eventInfo},
	{"ossl_h_from_hkey1", eventInfo},
	{"secret_binding_deny", eventRefused},
	{"secret_binding_audit", eventAudit},
	{"sni_captured", eventInfo},
	{"sni_deny", eventRefused},
	{"sni_audit", eventAudit},
	{"vip_dns_rewritten", eventInfo},
	// The answer kept the host's real addresses: the pod's connections to
	// it get no host-restricted secret.
	{"vip_dns_unchanged", eventUnrewritten},
	{"vip_connect_redirect", eventInfo},
	{"vip_connect_refused", eventRefused},
	{"vip_dns_unbound", eventInfo},
	{"vip_sock_host_deny", eventRefused},
	{"vip_sock_addr_deny", eventRefused},
}

// debugCounterNames are dataplaneEvents' names, by index.
var debugCounterNames = func() []string {
	names := make([]string, len(dataplaneEvents))
	for i, e := range dataplaneEvents {
		names[i] = e.name
	}
	return names
}()

// counterSource reads the data plane's event counters: one total per
// dataplaneEvents index, summed over CPUs.
type counterSource interface {
	readCounters() ([]uint64, error)
}

// dataplaneCollector is the Prometheus collector of the data plane's event
// counters (see the top of this file). Safe for concurrent use.
type dataplaneCollector struct {
	desc *prometheus.Desc

	mu     sync.Mutex
	source counterSource // nil: no data plane
	// last is what the source read last; base what earlier sources (or
	// values that went down) left, which the totals add.
	last, base []uint64
}

func newDataplaneCollector() *dataplaneCollector {
	return &dataplaneCollector{
		desc: prometheus.NewDesc("kloak_dataplane_events_total",
			"Events counted by the node's eBPF data plane, summed over CPUs. "+
				`class: "unrewritten" (a placeholder went out without its real value: a failure or a limit), `+
				`"refused" (the policy refused a rewrite, or a connect to a virtual IP), "dropped" (a packet the data plane dropped), `+
				`"audit" (what an audit mode let through), "info" (normal work, diagnostics).`,
			[]string{"event", "class"}, nil),
		last: make([]uint64, len(dataplaneEvents)),
		base: make([]uint64, len(dataplaneEvents)),
	}
}

// dataplaneMetrics is the controller's collector, on controller-runtime's
// registry (the metrics endpoint): the manager sets its source.
var dataplaneMetrics = newDataplaneCollector()

func init() {
	ctrlmetrics.Registry.MustRegister(dataplaneMetrics)
}

// setSource makes the collector read src. Another source than the one read
// last is another data plane, whose counters started at 0: the totals so
// far are kept, and src's add to them.
func (c *dataplaneCollector) setSource(src counterSource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if src == c.source {
		return
	}
	for i := range c.last {
		c.base[i] += c.last[i]
		c.last[i] = 0
	}
	c.source = src
}

// clearSource stops the collector reading src, if it reads it: before src
// is closed. The totals are kept for a next source (setSource).
func (c *dataplaneCollector) clearSource(src counterSource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.source == src {
		c.source = nil
	}
}

func (c *dataplaneCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

// Collect reads the source and reports every event's total. A value that
// went down (the counters started again) is a reset: the total carries on
// from what it reached. A failed read reports the last totals.
func (c *dataplaneCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.source == nil {
		return
	}
	if vals, err := c.source.readCounters(); err == nil {
		for i := range c.last {
			var v uint64
			if i < len(vals) {
				v = vals[i]
			}
			if v < c.last[i] {
				c.base[i] += c.last[i]
			}
			c.last[i] = v
		}
	}
	for i, e := range dataplaneEvents {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue,
			float64(c.base[i]+c.last[i]), e.name, string(e.class))
	}
}

// dataplaneTotals returns the counters' totals by event name, for logs.
func dataplaneTotals(src counterSource) (map[string]uint64, error) {
	vals, err := src.readCounters()
	if err != nil {
		return nil, err
	}
	if len(vals) < len(dataplaneEvents) {
		return nil, fmt.Errorf("%d counters, want %d", len(vals), len(dataplaneEvents))
	}
	out := make(map[string]uint64, len(dataplaneEvents))
	for i, e := range dataplaneEvents {
		out[e.name] = vals[i]
	}
	return out, nil
}
