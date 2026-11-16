//go:build linux

package ebpf

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// programContext names the context a program runs in, by its section: the
// contexts that can interrupt (or, for preemptible ones, be scheduled in
// between) each other's programs on the same CPU.
func programContext(section string) string {
	switch {
	case strings.HasPrefix(section, "uprobe/"), strings.HasPrefix(section, "uretprobe/"):
		return "uprobe"
	case strings.HasPrefix(section, "kprobe/"):
		return "kprobe"
	case strings.HasPrefix(section, "tracepoint/"):
		return "tracepoint"
	case strings.HasPrefix(section, "cgroup/"):
		return "cgroup"
	case section == "tc":
		return "tc"
	}
	return section
}

// TestPerCPUScratchPerContext checks that every per-CPU map is used by the
// programs of one context only. tc runs in softirq, which can interrupt a
// uprobe or kprobe program on the same CPU, and a uprobe program can be
// preempted by a task whose kprobe then runs there: a per-CPU scratch shared
// across contexts can be overwritten in the middle of a program (bpf_xor_path
// staged its patches in tc's ghash_work until kloak#383 phase 0). The debug
// counters are exempt: they only take atomic adds. The programs' instructions
// include the functions they call and their bpf_loop callbacks (the ELF
// reader links them in), not their tail calls, which are programs of their
// own, in the same context.
func TestPerCPUScratchPerContext(t *testing.T) {
	spec, err := loadTlsuprobe()
	if err != nil {
		t.Fatal(err)
	}

	users := map[string]map[string][]string{} // map -> context -> programs
	for _, name := range slices.Sorted(maps.Keys(spec.Programs)) {
		prog := spec.Programs[name]
		ctx := programContext(prog.SectionName)
		for _, ins := range prog.Instructions {
			if !ins.IsLoadFromMap() {
				continue
			}
			m := spec.Maps[ins.Reference()]
			if m == nil {
				continue
			}
			switch m.Type {
			case ebpf.PerCPUArray, ebpf.PerCPUHash, ebpf.LRUCPUHash:
			default:
				continue
			}
			if users[m.Name] == nil {
				users[m.Name] = map[string][]string{}
			}
			if !slices.Contains(users[m.Name][ctx], name) {
				users[m.Name][ctx] = append(users[m.Name][ctx], name)
			}
		}
	}

	// The scratch maps this test is about, so that it cannot pass by
	// finding no map at all.
	for m, ctx := range map[string]string{
		"scratch":       "uprobe",
		"uprobe_stage":  "uprobe",
		"kprobe_stage":  "kprobe",
		"ghash_scratch": "tc",
	} {
		if len(users[m][ctx]) == 0 {
			t.Errorf("no %s program uses %s", ctx, m)
		}
	}

	for _, m := range slices.Sorted(maps.Keys(users)) {
		if m == "debug_counters" {
			continue
		}
		if ctxs := users[m]; len(ctxs) > 1 {
			t.Errorf("per-CPU map %s is used from several contexts: %v", m, ctxs)
		}
	}
}
