//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"

	"github.com/spinningfactory/kloak/pkg/cgroups"
	"github.com/spinningfactory/kloak/pkg/logging"
)

// RunLifecycleSweep sweeps what kloak attached and stored for processes and
// containers that are gone (sweep), every interval until ctx is done.
func (m *TLSUprobeManager) RunLifecycleSweep(ctx context.Context, interval time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			m.sweep()
		}
	}
}

// sweepResult is what one sweep removed.
type sweepResult struct {
	uprobeLinks int // links of process-scoped uprobes of processes gone or re-exec'd
	mapEntries  int // entries of the cgroup-keyed BPF maps for cgroups gone
	tcRepaired  int // pod netns whose tc patch program was attached again
	tcReleased  int // pod netns no container is recorded in any more
}

// sweep removes what is left of processes and containers that went without
// kloak being told:
//
//   - the process-scoped uprobes (a Go, Bun or statically linked binary's)
//     of processes that exited or exec'd another binary: an exec probe that
//     runs such a binary attaches a uprobe for each run, which nothing else
//     detaches before the container goes;
//   - the entries of the BPF maps keyed by cgroup for cgroups that no
//     longer exist: the exec tracepoint records every container of the node
//     in tracked_cgroups (4096 entries), and a full map would refuse kloak's
//     own containers;
//   - and it checks the pods' tc patch programs with the kernel: one whose
//     interface was recreated is attached again.
func (m *TLSUprobeManager) sweep() sweepResult {
	var res sweepResult
	stale := m.registry.sweepProcesses(processCurrent)
	res.uprobeLinks = len(stale)
	m.detachAsync(stale, "uprobes of exited processes")

	n, err := m.gcCgroupMaps()
	res.mapEntries = n
	if err != nil {
		m.log.Warnw("lifecycle sweep: cleaning the cgroup-keyed BPF maps failed", "error", err)
	}

	res.tcRepaired, res.tcReleased = m.checkPodTC()

	uprobes, links := m.registry.counts()
	m.tcMu.Lock()
	netns := len(m.podTC)
	m.tcMu.Unlock()
	logging.Tracew(m.log, "lifecycle sweep",
		"uprobes", uprobes, "uprobeLinks", links, "podNetns", netns,
		"detachedUprobeLinks", res.uprobeLinks, "removedMapEntries", res.mapEntries,
		"tcRepaired", res.tcRepaired, "tcReleased", res.tcReleased)
	return res
}

// gcCgroupMaps deletes the entries of tracked_cgroups, tls_strategy and the
// offsets maps whose cgroup no longer exists, and returns how many it
// deleted. A cgroup is live while its directory is under the kubepods
// cgroup, or while kloak tracks it.
func (m *TLSUprobeManager) gcCgroupMaps() (int, error) {
	if m.kubepods == "" {
		return 0, nil // no kubepods cgroup: nothing tells which cgroups are live
	}
	// The maps' keys are read before the cgroups are: a cgroup created
	// while the tree is walked is not a candidate, whatever its entries.
	tracked, err := cgroupKeys(m.objs.TrackedCgroups)
	if err != nil {
		return 0, err
	}
	binaryMaps := []*ebpf.Map{m.objs.TlsStrategy, m.objs.TlsOffsetConfig, m.objs.GoTlsOffsetConfig}
	binary := make([][]tlsuprobeTlsBinaryKey, len(binaryMaps))
	for i, mp := range binaryMaps {
		if binary[i], err = binaryKeys(mp); err != nil {
			return 0, err
		}
	}
	live, err := liveCgroupIDs(m.kubepods)
	if err != nil {
		return 0, err
	}
	dead := func(id uint64) bool {
		if _, ok := live[id]; ok {
			return false
		}
		_, ok := m.cgroupPaths.Load(id)
		return !ok
	}

	n := 0
	var errs []error
	for _, id := range tracked {
		if !dead(id) {
			continue
		}
		if err := m.objs.TrackedCgroups.Delete(id); err == nil {
			n++
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("deleting cgroup %d from tracked_cgroups: %w", id, err))
		}
	}
	for i, mp := range binaryMaps {
		d, err := deleteBinaryKeysOf(mp, binary[i], dead)
		n += d
		if err != nil {
			errs = append(errs, err)
		}
	}
	return n, errors.Join(errs...)
}

// liveCgroupIDs returns the IDs (directory inodes) of the cgroups under
// root, root included.
func liveCgroupIDs(root string) (map[uint64]struct{}, error) {
	live := make(map[uint64]struct{})
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			// A cgroup removed during the walk.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			live[st.Ino] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking the cgroups under %s: %w", root, err)
	}
	return live, nil
}

// cgroupKeys returns the keys of tracked_cgroups.
func cgroupKeys(mp *ebpf.Map) ([]uint64, error) {
	var keys []uint64
	var prev any // nil: the first key
	for {
		var next uint64
		if err := mp.NextKey(prev, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return keys, nil
			}
			return keys, fmt.Errorf("iterating %s: %w", mp, err)
		}
		keys = append(keys, next)
		prev = &keys[len(keys)-1]
	}
}

// binaryKeys returns the keys of mp, a map keyed by tls_binary_key
// (cgroup_id, exe_inode).
func binaryKeys(mp *ebpf.Map) ([]tlsuprobeTlsBinaryKey, error) {
	var keys []tlsuprobeTlsBinaryKey
	var prev any // nil: the first key
	for {
		var next tlsuprobeTlsBinaryKey
		if err := mp.NextKey(prev, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return keys, nil
			}
			return keys, fmt.Errorf("iterating %s: %w", mp, err)
		}
		keys = append(keys, next)
		prev = &keys[len(keys)-1]
	}
}

// deleteBinaryKeysOf deletes from mp the keys whose cgroup drop reports, and
// returns how many it deleted.
func deleteBinaryKeysOf(mp *ebpf.Map, keys []tlsuprobeTlsBinaryKey, drop func(cgroupID uint64) bool) (int, error) {
	n := 0
	for i := range keys {
		if !drop(keys[i].CgroupId) {
			continue
		}
		if err := mp.Delete(&keys[i]); err == nil {
			n++
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return n, fmt.Errorf("deleting from %s: %w", mp, err)
		}
	}
	return n, nil
}

// deleteBinaryKeys deletes the entries of mp, a map keyed by tls_binary_key,
// whose cgroup drop reports, and returns how many it deleted.
func deleteBinaryKeys(mp *ebpf.Map, drop func(cgroupID uint64) bool) (int, error) {
	keys, err := binaryKeys(mp)
	if err != nil {
		return 0, err
	}
	return deleteBinaryKeysOf(mp, keys, drop)
}

// checkPodTC checks the pods' tc patch programs with the kernel. A pod netns
// one of whose attachments is gone (its veth was recreated) gets it again,
// through a process of a container tracked in the netns; one no container
// is recorded in any more is released. It returns how many it repaired and
// released.
func (m *TLSUprobeManager) checkPodTC() (repaired, released int) {
	m.tcMu.Lock()
	entries := maps.Clone(m.podTC)
	m.tcMu.Unlock()

	refs := make(map[uint64][]uint64) // netns inode -> the cgroups recorded in it
	m.cgroupToNetns.Range(func(k, v any) bool {
		refs[v.(uint64)] = append(refs[v.(uint64)], k.(uint64))
		return true
	})

	for ino, e := range entries {
		if len(refs[ino]) == 0 {
			m.releasePodTC(ino)
			released++
			continue
		}
		e.mu.Lock()
		stale := e.attached && !e.released && !m.podTCLive(e)
		e.mu.Unlock()
		if !stale {
			continue
		}
		if m.reattachPodTC(ino, refs[ino]) {
			repaired++
		}
	}
	return repaired, released
}

// reattachPodTC attaches the tc patch program of netns netnsIno again,
// through a process of one of the tracked containers cgroupIDs, and reports
// whether it did.
func (m *TLSUprobeManager) reattachPodTC(netnsIno uint64, cgroupIDs []uint64) bool {
	for _, cg := range cgroupIDs {
		path, ok := m.cgroupPaths.Load(cg)
		if !ok {
			continue // a container that exited
		}
		pids, err := cgroups.ReadCgroupProcs(path.(string))
		if err != nil {
			continue
		}
		for _, pid := range pids {
			if ino, err := netnsInode(fmt.Sprintf("/proc/%d/ns/net", pid)); err != nil || ino != netnsIno {
				continue
			}
			if err := m.attachTCEgress(pid, cg); err != nil {
				m.log.Warnw("lifecycle sweep: a pod's tc patch program is gone from an interface, and attaching it again failed; secrets will not be rewritten",
					"netns_ino", netnsIno, "pid", pid, "error", err)
				return false
			}
			m.log.Infow("lifecycle sweep: attached a pod's tc patch program again, an interface of its netns was recreated",
				"netns_ino", netnsIno, "pid", pid, "cgroupID", cg)
			return true
		}
	}
	return false
}
