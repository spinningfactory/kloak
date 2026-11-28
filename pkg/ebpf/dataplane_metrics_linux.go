//go:build linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// debugCounterMap reads debug_counters (a per-CPU array of u64): each
// dataplaneEvents index's values, summed over the CPUs.
type debugCounterMap struct {
	m *ebpf.Map
}

func (d debugCounterMap) readCounters() ([]uint64, error) {
	if d.m == nil {
		return nil, fmt.Errorf("no debug_counters map")
	}
	out := make([]uint64, len(dataplaneEvents))
	var perCPU []uint64
	for i := range out {
		if err := d.m.Lookup(uint32(i), &perCPU); err != nil {
			return nil, fmt.Errorf("reading debug_counters[%d]: %w", i, err)
		}
		for _, v := range perCPU {
			out[i] += v
		}
	}
	return out, nil
}
