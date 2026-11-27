package ebpf

import (
	"errors"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// cDebugCounters returns the names of the DBG_* enum in bpf/tls_uprobe.c,
// in order, as dataplaneEvents names them (lowercased, without DBG_).
func cDebugCounters(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("bpf/tls_uprobe.c")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)enum \{\s*\n(\s*DBG_XOR_CONN_CHECK.*?)\n\s*DBG_MAX,`).FindSubmatch(src)
	if block == nil {
		t.Fatal("no DBG_* enum ending in DBG_MAX in bpf/tls_uprobe.c")
	}
	var names []string
	entry := regexp.MustCompile(`^\s*DBG_([A-Z0-9_]+)\s*(?:=\s*0\s*)?,`)
	for _, line := range strings.Split(string(block[1]), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		m := entry.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("unexpected line in the DBG_* enum (one constant per line, no values but the first = 0): %q", line)
		}
		names = append(names, strings.ToLower(m[1]))
	}
	return names
}

// TestDataplaneEventsMatchEnum checks that dataplaneEvents names the
// DBG_* enum's counters in its order, and gives each a class: the metrics
// read debug_counters by those indexes.
func TestDataplaneEventsMatchEnum(t *testing.T) {
	want := cDebugCounters(t)
	if !slices.Equal(debugCounterNames, want) {
		for i := 0; i < max(len(want), len(debugCounterNames)); i++ {
			var c, g string
			if i < len(want) {
				c = want[i]
			}
			if i < len(debugCounterNames) {
				g = debugCounterNames[i]
			}
			if c != g {
				t.Fatalf("debug_counters index %d is DBG_%s in bpf/tls_uprobe.c, %q in dataplaneEvents: add {%q, <class>} to dataplaneEvents at index %d (dataplane_metrics.go)",
					i, strings.ToUpper(c), g, c, i)
			}
		}
	}
	for _, e := range dataplaneEvents {
		switch e.class {
		case eventUnrewritten, eventRefused, eventDropped, eventAudit, eventInfo:
		default:
			t.Errorf("%s: class %q", e.name, e.class)
		}
	}
	src, err := os.ReadFile("bpf/tls_uprobe.c")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`__uint\(max_entries, (\d+)\); // must be >= DBG_MAX`).FindSubmatch(src)
	if m == nil || len(m[1]) == 0 {
		t.Fatal("no debug_counters max_entries")
	}
	if n, _ := strconv.Atoi(string(m[1])); len(dataplaneEvents) > n {
		t.Errorf("%d counters, debug_counters holds %d", len(dataplaneEvents), n)
	}
}

// fakeCounters is a counterSource with given totals, or an error.
type fakeCounters struct {
	vals []uint64
	err  error
}

func (f *fakeCounters) readCounters() ([]uint64, error) { return f.vals, f.err }

// gatherEvents collects c and returns its totals by event, with each
// event's class.
func gatherEvents(t *testing.T, c *dataplaneCollector) (map[string]float64, map[string]string) {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	vals, classes := map[string]float64{}, map[string]string{}
	for _, f := range families {
		if f.GetName() != "kloak_dataplane_events_total" {
			t.Fatalf("metric %s", f.GetName())
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			vals[labels["event"]] = m.GetCounter().GetValue()
			classes[labels["event"]] = labels["class"]
		}
	}
	return vals, classes
}

func counters(set map[string]uint64) []uint64 {
	out := make([]uint64, len(dataplaneEvents))
	for name, v := range set {
		out[slices.Index(debugCounterNames, name)] = v
	}
	return out
}

// TestDataplaneCollector checks the exported totals: every event, with its
// class, from the source; monotonic when the counters start again (a data
// plane loaded again, another source) or go on (one adopted); the last
// totals when a read fails; nothing without a source.
func TestDataplaneCollector(t *testing.T) {
	c := newDataplaneCollector()
	if vals, _ := gatherEvents(t, c); len(vals) != 0 {
		t.Fatalf("%d series without a source", len(vals))
	}

	src := &fakeCounters{vals: counters(map[string]uint64{"tc_patched": 7, "sni_deny": 2})}
	c.setSource(src)
	vals, classes := gatherEvents(t, c)
	if len(vals) != len(dataplaneEvents) {
		t.Fatalf("%d series, want one per event (%d)", len(vals), len(dataplaneEvents))
	}
	if vals["tc_patched"] != 7 || vals["sni_deny"] != 2 || vals["tc_entry"] != 0 {
		t.Errorf("totals %v", vals)
	}
	if classes["sni_deny"] != "refused" || classes["tc_patched"] != "info" || classes["kprobe_bridge_h_fail"] != "unrewritten" {
		t.Errorf("classes %v", classes)
	}

	// Counting on.
	src.vals = counters(map[string]uint64{"tc_patched": 10, "sni_deny": 2})
	if vals, _ = gatherEvents(t, c); vals["tc_patched"] != 10 {
		t.Errorf("tc_patched %v, want 10", vals["tc_patched"])
	}

	// A failed read: the last totals.
	src.err = errors.New("map closed")
	if vals, _ = gatherEvents(t, c); vals["tc_patched"] != 10 || len(vals) != len(dataplaneEvents) {
		t.Errorf("after a failed read: %d series, tc_patched %v", len(vals), vals["tc_patched"])
	}

	// The data plane loaded again: its counters start at 0. The totals carry
	// on from 10 and 2.
	c.clearSource(&fakeCounters{}) // another source's clear changes nothing
	reloaded := &fakeCounters{vals: counters(map[string]uint64{"tc_patched": 3})}
	c.clearSource(src)
	if vals, _ = gatherEvents(t, c); len(vals) != 0 {
		t.Errorf("%d series after the source was cleared", len(vals))
	}
	c.setSource(reloaded)
	if vals, _ = gatherEvents(t, c); vals["tc_patched"] != 13 || vals["sni_deny"] != 2 {
		t.Errorf("after a reload: tc_patched %v (want 13), sni_deny %v (want 2)", vals["tc_patched"], vals["sni_deny"])
	}
	reloaded.vals = counters(map[string]uint64{"tc_patched": 5, "sni_deny": 1})
	if vals, _ = gatherEvents(t, c); vals["tc_patched"] != 15 || vals["sni_deny"] != 3 {
		t.Errorf("counting on after a reload: tc_patched %v (want 15), sni_deny %v (want 3)", vals["tc_patched"], vals["sni_deny"])
	}

	// The counters going down on the same source: a reset too.
	reloaded.vals = counters(map[string]uint64{"tc_patched": 1, "sni_deny": 1})
	if vals, _ = gatherEvents(t, c); vals["tc_patched"] != 16 || vals["sni_deny"] != 3 {
		t.Errorf("a reset in place: tc_patched %v (want 15 + 1), sni_deny %v (want 3)", vals["tc_patched"], vals["sni_deny"])
	}

	// A data plane that already counted past the totals when it is set adds
	// to them all the same.
	c.setSource(&fakeCounters{vals: counters(map[string]uint64{"tc_patched": 40})})
	if vals, _ = gatherEvents(t, c); vals["tc_patched"] != 56 || vals["sni_deny"] != 3 {
		t.Errorf("another data plane: tc_patched %v (want 16 + 40), sni_deny %v (want 3)", vals["tc_patched"], vals["sni_deny"])
	}

	// A controller restarted on the pinned data plane (a new process: a new
	// collector) reports the counters as the map holds them, which carry on
	// from the previous controller's: no reset for Prometheus.
	next := newDataplaneCollector()
	next.setSource(&fakeCounters{vals: counters(map[string]uint64{"tc_patched": 41})})
	if vals, _ = gatherEvents(t, next); vals["tc_patched"] != 41 {
		t.Errorf("an adopted data plane: tc_patched %v, want the map's 41", vals["tc_patched"])
	}
}

// TestDataplaneTotals checks the totals the debug log prints.
func TestDataplaneTotals(t *testing.T) {
	got, err := dataplaneTotals(&fakeCounters{vals: counters(map[string]uint64{"xor_delta_done": 4})})
	if err != nil || got["xor_delta_done"] != 4 || len(got) != len(dataplaneEvents) {
		t.Errorf("dataplaneTotals = %v, %v", got, err)
	}
	if _, err := dataplaneTotals(&fakeCounters{vals: []uint64{1}}); err == nil {
		t.Error("a short read was accepted")
	}
}

// TestAlertClasses keeps the README's alert set in step with the classes.
func TestAlertClasses(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range alertClasses {
		if !strings.Contains(string(readme), "`"+string(c)+"`") {
			t.Errorf("README.md's Metrics section does not describe class %q", c)
		}
	}
}

// TestDataplaneMetricsRegistered checks that the collector is on
// controller-runtime's registry, which the controller's metrics endpoint
// serves: another collector of the same metric is refused there.
func TestDataplaneMetricsRegistered(t *testing.T) {
	var already prometheus.AlreadyRegisteredError
	if err := ctrlmetrics.Registry.Register(newDataplaneCollector()); !errors.As(err, &already) {
		t.Errorf("registering kloak_dataplane_events_total again: %v, want AlreadyRegisteredError", err)
	}
}
