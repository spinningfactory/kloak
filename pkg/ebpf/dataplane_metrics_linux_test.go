//go:build linux

package ebpf

import (
	"slices"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
)

// TestDebugCounterMapReadsEveryCPU checks that the metrics read each
// counter of debug_counters (the real map's layout) summed over every
// possible CPU, and that the map holds every event.
func TestDebugCounterMapReadsEveryCPU(t *testing.T) {
	m := createTestMap(t, "debug_counters")
	if int(m.MaxEntries()) < len(dataplaneEvents) {
		t.Fatalf("debug_counters holds %d counters, there are %d events", m.MaxEntries(), len(dataplaneEvents))
	}
	ncpu, err := ciliumebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	idx := slices.Index(debugCounterNames, "sni_deny")
	perCPU := make([]uint64, ncpu)
	for i := range perCPU {
		perCPU[i] = uint64(i + 1)
	}
	if err := m.Update(uint32(idx), perCPU, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	vals, err := debugCounterMap{m}.readCounters()
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range vals {
		want := uint64(0)
		if i == idx {
			want = uint64(ncpu * (ncpu + 1) / 2)
		}
		if v != want {
			t.Errorf("%s: %d, want %d", debugCounterNames[i], v, want)
		}
	}
}

// TestDataplaneEventsCounted runs tc_egress_patch, which counts tc_entry
// for every packet, and checks the metric: the BPF object's DBG_TC_ENTRY is
// the index dataplaneEvents names tc_entry.
func TestDataplaneEventsCounted(t *testing.T) {
	objs := loadTestObjects(t)
	c := newDataplaneCollector()
	c.setSource(debugCounterMap{objs.DebugCounters})
	before, _ := gatherEvents(t, c)

	// An Ethernet frame of no protocol tc handles: counted, then passed on.
	frame := make([]byte, 64)
	for range 3 {
		if _, err := objs.TcEgressPatch.Run(&ciliumebpf.RunOptions{Data: frame}); err != nil {
			t.Skipf("BPF_PROG_TEST_RUN: %v", err)
		}
	}
	after, classes := gatherEvents(t, c)
	if got := after["tc_entry"] - before["tc_entry"]; got != 3 {
		t.Errorf("tc_entry went up by %v, want 3 (the counters %v)", got, after)
	}
	if classes["tc_entry"] != string(eventInfo) {
		t.Errorf("tc_entry is class %q", classes["tc_entry"])
	}
	for name, v := range after {
		if name != "tc_entry" && v != before[name] {
			t.Errorf("%s went from %v to %v", name, before[name], v)
		}
	}
}
