//go:build linux

package ebpf

// Keeping the data plane across controller restarts (spinningfactory/kloak#107,
// Phase 1).
//
// Every BPF object kloak loads or attaches is pinned in bpffs, so that it
// outlives the controller: a controller that restarts with the same build
// adopts what the previous one left there, and the pods' TLS writes are
// rewritten all along. The layout under the pin root (DefaultBPFPinPath):
//
//	meta                             ARRAY: the layout's format, the active build
//	dispatch/kloak_dispatch          the uprobe trampolines' slots (dispatch_v1.c)
//	dispatch/<program>               the trampolines
//	gens/<build>/ready               made once the build's programs and maps are pinned
//	gens/<build>/maps/<map>          the build's maps
//	gens/<build>/progs/<program>     its programs
//	gens/<build>/links/global/<name> its node-wide links (tracepoints, kprobes, cgroup hooks)
//	gens/<build>/links/tcx/<link ID> its TCX links (the pods' tc patch and DNS rewrite)
//	links/uprobe/<key>               the uprobes, on the trampolines (uprobePinName)
//	vip_host_ip, vip_ip_host, vip_upstream  the virtual IP state (virtual_ip_linux.go)
//
// A build is the BPF object kloak embeds (with pipelineABI): one whose
// programs or map layouts differ is another build, and the controller then
// tears down the previous one's (teardownGen) and loads its own. The uprobes
// are on the trampolines, not on a build's programs, so they are kept: the
// build's entry programs are put in the trampolines' slots.
//
// Pins are made with the attach (attach, then pin, then record): a crash in
// between leaves a link only the dead process's fd held, which went with it.
//
// The pins hold real secrets (secret_map): the root is 0700, and readable by
// the node's root only, as the maps already are with bpftool.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// pipelineABI changes when the controller would read or write what an
// earlier build left in the pins differently, though the BPF object is the
// same (what Go pushes into a map, how a pin is named): it is part of the
// build's identity, so such a change is a new build.
const pipelineABI = 1

// pinFormat is the layout described above, recorded in meta. A controller
// that finds another tears down everything but the virtual IP state.
const pinFormat = 1

// meta's indexes: the format, and the active build's 32 bytes in four u64s.
const (
	metaFormat     = 0
	metaBuild      = 1
	metaMaxEntries = 8
)

// The kloak_dispatch slots (KLOAK_DISPATCH_* in dispatch_v1.c). Frozen: the
// pinned trampolines of a running node tail-call them.
const (
	dispatchSlotSSLWrite   = 0
	dispatchSlotGoTLSWrite = 1
	dispatchSlotEVPInit    = 2
	dispatchSlotEVPInitRet = 3
	dispatchSlots          = 4
)

// The maps teardownGen empties to make what is left of a build inert.
const (
	vipConfigMap = "vip_config"
	secretMapMap = "secret_map"
)

// buildID returns the identity of the BPF pipeline this binary embeds:
// SHA-256 of its object and pipelineABI, in hex.
func buildID() string {
	h := sha256.New()
	h.Write(_TlsuprobeBytes)
	_ = binary.Write(h, binary.LittleEndian, uint64(pipelineABI))
	return hex.EncodeToString(h.Sum(nil))
}

// pinRoot is the pin root of a node whose bpffs is the host's, so that pins
// outlive the controller's container.
type pinRoot struct {
	dir   string
	build string // buildID
	log   *zap.SugaredLogger
}

func (r *pinRoot) metaPath() string      { return filepath.Join(r.dir, "meta") }
func (r *pinRoot) dispatchDir() string   { return filepath.Join(r.dir, "dispatch") }
func (r *pinRoot) gensDir() string       { return filepath.Join(r.dir, "gens") }
func (r *pinRoot) genDir() string        { return filepath.Join(r.gensDir(), r.build) }
func (r *pinRoot) uprobeDir() string     { return filepath.Join(r.dir, "links", "uprobe") }
func (r *pinRoot) globalLinkDir() string { return filepath.Join(r.genDir(), "links", "global") }
func (r *pinRoot) tcxLinkDir() string    { return filepath.Join(r.genDir(), "links", "tcx") }
func (r *pinRoot) tcxPin(id link.ID) string {
	return filepath.Join(r.tcxLinkDir(), strconv.FormatUint(uint64(id), 10))
}

// openPinRoot returns the pin root at dir, or an error saying why the
// objects can't be kept there: dir must be on a bpffs mount that is the
// host's (the same as /proc/1/root's, the controller runs with hostPID), or
// the pins would go with the container's mount namespace.
func openPinRoot(dir string, log *zap.SugaredLogger) (*pinRoot, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("pin root %q is not an absolute path", dir)
	}
	if err := requireBPFFS(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating the pin root: %w", err)
	}
	var ours, host unix.Stat_t
	if err := unix.Stat(dir, &ours); err != nil {
		return nil, err
	}
	hostDir := "/proc/1/root" + filepath.Clean(dir)
	if err := unix.Stat(hostDir, &host); err != nil {
		return nil, fmt.Errorf("%s is not the host's bpffs (%s: %w)", dir, hostDir, err)
	}
	if ours.Dev != host.Dev || ours.Ino != host.Ino {
		return nil, fmt.Errorf("%s is not the host's bpffs: it is not %s", dir, hostDir)
	}
	return &pinRoot{dir: dir, build: buildID(), log: log}, nil
}

// prepare readies the pin root for this build: it tears down what this
// controller won't adopt (another layout, another build's or an incomplete
// generation), and reports whether this build's generation is there, ready
// to adopt.
func (r *pinRoot) prepare() (adoptable bool, err error) {
	format, _, err := readMeta(r.metaPath())
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		r.log.Warnw("pinned BPF objects: unreadable meta, tearing them down", "error", err)
		format = -1
	}
	if format != 0 && format != pinFormat {
		// Another layout: nothing in it can be trusted to mean what this
		// controller would read in it.
		r.log.Warnw("pinned BPF objects have another layout, tearing them down", "format", format, "want", pinFormat)
		if err := teardownPins(r.dir, false, r.log); err != nil {
			return false, err
		}
	}
	entries, err := os.ReadDir(r.gensDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	for _, e := range entries {
		dir := filepath.Join(r.gensDir(), e.Name())
		if e.Name() == r.build && dirExists(filepath.Join(dir, "ready")) {
			adoptable = true
			continue
		}
		reason := "another build"
		if e.Name() == r.build {
			reason = "an incomplete load"
		}
		r.log.Infow("tearing down pinned BPF objects of "+reason, "build", e.Name())
		if err := teardownGen(dir, r.log); err != nil {
			return false, err
		}
	}
	if err := os.MkdirAll(r.uprobeDir(), 0o700); err != nil {
		return false, err
	}
	return adoptable, nil
}

// writeMeta records the format and this build as the active one.
func (r *pinRoot) writeMeta() error {
	m, err := ebpf.LoadPinnedMap(r.metaPath(), nil)
	if errors.Is(err, os.ErrNotExist) {
		m, err = ebpf.NewMap(&ebpf.MapSpec{
			Name: "kloak_meta", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: metaMaxEntries,
		})
		if err == nil {
			err = m.Pin(r.metaPath())
		}
	}
	if err != nil {
		return fmt.Errorf("opening meta: %w", err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Update(uint32(metaFormat), uint64(pinFormat), ebpf.UpdateAny); err != nil {
		return err
	}
	id, err := hex.DecodeString(r.build)
	if err != nil || len(id) != 32 {
		return fmt.Errorf("build ID %q", r.build)
	}
	for i := 0; i < 4; i++ {
		if err := m.Update(uint32(metaBuild+i), binary.LittleEndian.Uint64(id[i*8:]), ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

// readMeta returns the format and the active build recorded in meta at path.
func readMeta(path string) (format int, build string, err error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = m.Close() }()
	if m.Type() != ebpf.Array || m.KeySize() != 4 || m.ValueSize() != 8 || m.MaxEntries() < metaBuild+4 {
		return 0, "", fmt.Errorf("meta is %v with %d-byte values", m.Type(), m.ValueSize())
	}
	var v uint64
	if err := m.Lookup(uint32(metaFormat), &v); err != nil {
		return 0, "", err
	}
	id := make([]byte, 32)
	for i := 0; i < 4; i++ {
		var w uint64
		if err := m.Lookup(uint32(metaBuild+i), &w); err != nil {
			return 0, "", err
		}
		binary.LittleEndian.PutUint64(id[i*8:], w)
	}
	return int(v), hex.EncodeToString(id), nil
}

// objectFields returns pointers to the program and map fields of objs, a
// pointer to a bpf2go objects struct, by their ebpf tags.
func objectFields(objs any) (progs map[string]**ebpf.Program, maps map[string]**ebpf.Map) {
	progs = make(map[string]**ebpf.Program)
	maps = make(map[string]**ebpf.Map)
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f, fv := t.Field(i), v.Field(i)
			if f.Anonymous && f.Type.Kind() == reflect.Struct {
				walk(fv)
				continue
			}
			name := f.Tag.Get("ebpf")
			if name == "" {
				continue
			}
			switch p := fv.Addr().Interface().(type) {
			case **ebpf.Program:
				progs[name] = p
			case **ebpf.Map:
				maps[name] = p
			}
		}
	}
	walk(reflect.ValueOf(objs).Elem())
	return progs, maps
}

// pinGeneration pins the programs and maps of objs, this build's pipeline
// just loaded, under the generation's directory, and marks it ready. The
// virtual IP maps are pinned at the root already.
func (r *pinRoot) pinGeneration(objs *tlsuprobeObjects) error {
	dir := r.genDir()
	for _, d := range []string{"maps", "progs", filepath.Join("links", "global"), filepath.Join("links", "tcx")} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return err
		}
	}
	progs, maps := objectFields(objs)
	for name, p := range progs {
		if err := (*p).Pin(filepath.Join(dir, "progs", name)); err != nil {
			return fmt.Errorf("pinning program %s: %w", name, err)
		}
	}
	for name, m := range maps {
		if isVirtualIPMap(name) {
			continue
		}
		if err := (*m).Pin(filepath.Join(dir, "maps", name)); err != nil {
			return fmt.Errorf("pinning map %s: %w", name, err)
		}
	}
	return os.Mkdir(filepath.Join(dir, "ready"), 0o700)
}

// loadGeneration fills objs with this build's pinned programs and maps, and
// checks them against spec: a program or map of another type or layout
// means the pins are not this build's, and are not adopted. The virtual IP
// maps are the root's, and must be the ones the programs use.
func (r *pinRoot) loadGeneration(spec *ebpf.CollectionSpec, objs *tlsuprobeObjects) (err error) {
	dir := r.genDir()
	defer func() {
		if err != nil {
			_ = objs.Close()
			*objs = tlsuprobeObjects{}
		}
	}()
	progs, maps := objectFields(objs)
	used := make(map[ebpf.MapID]bool)
	for name, p := range progs {
		ps, ok := spec.Programs[name]
		if !ok {
			return fmt.Errorf("program %s is not in the BPF object", name)
		}
		prog, err := ebpf.LoadPinnedProgram(filepath.Join(dir, "progs", name), nil)
		if err != nil {
			return fmt.Errorf("loading pinned program %s: %w", name, err)
		}
		*p = prog
		if prog.Type() != ps.Type {
			return fmt.Errorf("pinned program %s is %v, want %v", name, prog.Type(), ps.Type)
		}
		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("pinned program %s: %w", name, err)
		}
		ids, _ := info.MapIDs()
		for _, id := range ids {
			used[id] = true
		}
	}
	for name, m := range maps {
		ms, ok := spec.Maps[name]
		if !ok {
			return fmt.Errorf("map %s is not in the BPF object", name)
		}
		path := filepath.Join(dir, "maps", name)
		if isVirtualIPMap(name) {
			path = filepath.Join(r.dir, name)
		}
		mp, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			return fmt.Errorf("loading pinned map %s: %w", name, err)
		}
		*m = mp
		if err := ms.Compatible(mp); err != nil {
			return fmt.Errorf("pinned map %s: %w", name, err)
		}
		if isVirtualIPMap(name) {
			info, err := mp.Info()
			if err != nil {
				return fmt.Errorf("pinned map %s: %w", name, err)
			}
			if id, _ := info.ID(); !used[id] {
				return fmt.Errorf("pinned map %s is not the one the pinned programs use", name)
			}
		}
	}
	return nil
}

func isVirtualIPMap(name string) bool {
	for _, n := range virtualIPMaps {
		if n == name {
			return true
		}
	}
	return false
}

// openDispatch returns the uprobe trampolines: the pinned ones when r holds
// valid ones (adopted), loaded (and pinned with r) otherwise. Loading new
// trampolines drops the pinned uprobes: they run the previous ones, whose
// slots nothing fills any more.
func openDispatch(r *pinRoot) (objs *dispatchObjects, adopted bool, err error) {
	objs = &dispatchObjects{}
	if r != nil {
		if err := r.loadPinnedDispatch(objs); err == nil {
			return objs, true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			r.log.Warnw("pinned uprobe trampolines can't be used, loading them again; the pinned uprobes are detached",
				"error", err)
		}
		if err := removePins(r.uprobeDir()); err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(r.uprobeDir(), 0o700); err != nil {
			return nil, false, err
		}
		if err := os.RemoveAll(r.dispatchDir()); err != nil {
			return nil, false, err
		}
	}
	if err := loadDispatchObjects(objs, nil); err != nil {
		return nil, false, fmt.Errorf("loading the uprobe trampolines: %w", err)
	}
	if r == nil {
		return objs, false, nil
	}
	if err := os.MkdirAll(r.dispatchDir(), 0o700); err != nil {
		_ = objs.Close()
		return nil, false, err
	}
	progs, maps := objectFields(objs)
	for name, p := range progs {
		if err := (*p).Pin(filepath.Join(r.dispatchDir(), name)); err != nil {
			_ = objs.Close()
			return nil, false, fmt.Errorf("pinning trampoline %s: %w", name, err)
		}
	}
	for name, m := range maps {
		if err := (*m).Pin(filepath.Join(r.dispatchDir(), name)); err != nil {
			_ = objs.Close()
			return nil, false, fmt.Errorf("pinning %s: %w", name, err)
		}
	}
	return objs, false, nil
}

// loadPinnedDispatch fills objs with the pinned trampolines, checking them
// against the embedded object. It returns an error wrapping os.ErrNotExist
// when none are pinned.
func (r *pinRoot) loadPinnedDispatch(objs *dispatchObjects) (err error) {
	spec, err := loadDispatch()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = objs.Close()
			*objs = dispatchObjects{}
		}
	}()
	progs, maps := objectFields(objs)
	for name, p := range progs {
		prog, err := ebpf.LoadPinnedProgram(filepath.Join(r.dispatchDir(), name), nil)
		if err != nil {
			return fmt.Errorf("loading pinned trampoline %s: %w", name, err)
		}
		*p = prog
		if ps := spec.Programs[name]; ps == nil || prog.Type() != ps.Type {
			return fmt.Errorf("pinned trampoline %s is %v", name, prog.Type())
		}
	}
	for name, m := range maps {
		mp, err := ebpf.LoadPinnedMap(filepath.Join(r.dispatchDir(), name), nil)
		if err != nil {
			return fmt.Errorf("loading pinned %s: %w", name, err)
		}
		*m = mp
		ms := spec.Maps[name]
		if ms == nil {
			return fmt.Errorf("pinned %s is not in the trampolines' object", name)
		}
		if err := ms.Compatible(mp); err != nil {
			return fmt.Errorf("pinned %s: %w", name, err)
		}
	}
	return nil
}

// fillDispatch puts the pipeline's entry programs in the trampolines' slots.
func fillDispatch(d *dispatchObjects, objs *tlsuprobeObjects) error {
	for slot, prog := range map[uint32]*ebpf.Program{
		dispatchSlotSSLWrite:   objs.BpfUprobeSslWrite,
		dispatchSlotGoTLSWrite: objs.BpfUprobeGoTlsWrite,
		dispatchSlotEVPInit:    objs.BpfUprobeEvpCipherInit,
		dispatchSlotEVPInitRet: objs.BpfUretprobeEvpCipherInit,
	} {
		if err := d.KloakDispatch.Update(slot, uint32(prog.FD()), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("filling trampoline slot %d: %w", slot, err)
		}
	}
	return nil
}

// clearDispatch empties the trampolines' slots of the kloak_dispatch map
// m: every kloak uprobe does nothing from then on.
func clearDispatch(m *ebpf.Map) error {
	var errs []error
	for slot := uint32(0); slot < m.MaxEntries(); slot++ {
		if err := m.Delete(slot); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ownedLink is a link kloak attached, with the pin that keeps it attached
// across controller restarts ("" if it is not pinned). Close detaches it;
// release only lets go of this process's handle.
type ownedLink struct {
	link.Link
	pin string
}

// Close unpins and closes the link, which detaches it.
func (l *ownedLink) Close() error {
	if l.pin != "" {
		if err := os.Remove(l.pin); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("unpinning %s: %w", l.pin, err)
		}
	}
	return l.Link.Close()
}

// release closes this process's handle: a pinned link stays attached.
func (l *ownedLink) release() error { return l.Link.Close() }

// releaser is an attachment that can outlive the controller: release lets
// go of the controller's handle on it without detaching it.
type releaser interface{ release() error }

// pinOnce rate-limits the warning about links that can't be pinned.
var pinOnce sync.Once

// pinLink pins l at path (when r is not nil) and returns it as an
// ownedLink. A link that can't be pinned still works, but goes with this
// controller.
func (r *pinRoot) pinLink(l link.Link, path string) *ownedLink {
	if r == nil {
		return &ownedLink{Link: l}
	}
	if err := l.Pin(path); err != nil {
		pinOnce.Do(func() {
			r.log.Warnw("a BPF link can't be pinned: it will be detached with this controller, and attached again by the next one",
				"pin", path, "error", err)
		})
		return &ownedLink{Link: l}
	}
	return &ownedLink{Link: l, pin: path}
}

// uprobePinVersion names the uprobeLinkKey encoding of uprobePinName. A
// change in how a key is computed or encoded is a new version: pins of
// another one are detached (and attached again by the reconciliation).
const uprobePinVersion = "u1"

// uprobePinSep separates the fields of a uprobe pin name.
const uprobePinSep = "+"

// uprobePinName is the pin name of link idx of the uprobe key: every field
// of the key, so that a controller reads the key back from the pin
// (parseUprobePinName). The fields are separated by '+', which neither the
// numbers, the hex handle nor the base64url symbol use (bpffs reserves '.'
// in names). It reports false for a key too long for a file name, which is
// not pinned.
func uprobePinName(k *uprobeLinkKey, idx int) (string, bool) {
	name := strings.Join([]string{
		uprobePinVersion,
		strconv.FormatUint(uint64(k.prog), 10),
		strconv.Itoa(k.pid),
		strconv.FormatUint(k.start, 10),
		strconv.FormatUint(k.file.dev, 16),
		strconv.FormatUint(k.file.ino, 16),
		strconv.FormatInt(k.file.ctime, 10),
		k.file.handle, // hex (fileIdentity)
		strconv.FormatUint(k.addr, 16),
		base64.RawURLEncoding.EncodeToString([]byte(k.symbol)),
		strconv.Itoa(idx),
	}, uprobePinSep)
	return name, len(name) <= 255
}

// parseUprobePinName is the inverse of uprobePinName.
func parseUprobePinName(name string) (k uprobeLinkKey, idx int, err error) {
	f := strings.Split(name, uprobePinSep)
	if len(f) != 11 || f[0] != uprobePinVersion {
		return k, 0, fmt.Errorf("uprobe pin %q: not a %s name", name, uprobePinVersion)
	}
	var errs []error
	num := func(s string, base, bits int) uint64 {
		v, err := strconv.ParseUint(s, base, bits)
		errs = append(errs, err)
		return v
	}
	k.prog = uprobeProg(num(f[1], 10, 8))
	k.pid = int(num(f[2], 10, 31))
	k.start = num(f[3], 10, 64)
	k.file.dev = num(f[4], 16, 64)
	k.file.ino = num(f[5], 16, 64)
	ctime, err := strconv.ParseInt(f[6], 10, 64)
	errs = append(errs, err)
	k.file.ctime = ctime
	if _, err := hex.DecodeString(f[7]); err != nil {
		errs = append(errs, err)
	}
	k.file.handle = f[7]
	k.addr = num(f[8], 16, 64)
	sym, err := base64.RawURLEncoding.DecodeString(f[9])
	errs = append(errs, err)
	k.symbol = string(sym)
	idx = int(num(f[10], 10, 8))
	if err := errors.Join(errs...); err != nil {
		return k, 0, fmt.Errorf("uprobe pin %q: %w", name, err)
	}
	if k.prog < progSSLWrite || k.prog > progEVPCipherInit || idx >= k.prog.links() {
		return k, 0, fmt.Errorf("uprobe pin %q: program %d, link %d", name, k.prog, idx)
	}
	return k, idx, nil
}

// links returns how many links a uprobe running p has.
func (p uprobeProg) links() int {
	if p == progEVPCipherInit {
		return 2 // the entry and the return probe
	}
	return 1
}

// removePins removes the pins in dir and dir itself; a missing dir is not
// an error.
func removePins(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing %s: %w", dir, err)
	}
	return nil
}

// teardownGen makes what is left of the generation at dir inert, and
// removes its pins. Unpinning detaches the links no process holds; a cls_bpf
// filter (a classic tc filter, not a link) outlives every handle, and keeps
// running a program of the generation until its interface goes: emptying
// vip_config and secret_map first leaves it nothing to rewrite.
func teardownGen(dir string, log *zap.SugaredLogger) error {
	var errs []error
	if err := emptyPinnedMap(filepath.Join(dir, "maps", vipConfigMap), true); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("disabling %s: %w", vipConfigMap, err))
	}
	if err := emptyPinnedMap(filepath.Join(dir, "maps", secretMapMap), false); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("emptying %s: %w", secretMapMap, err))
	}
	// The tc programs first (no packet is patched once they are gone), then
	// the probes that feed them, then the programs and maps.
	for _, sub := range []string{filepath.Join("links", "tcx"), filepath.Join("links", "global"), "links", "progs", "maps"} {
		if err := removePins(filepath.Join(dir, sub)); err != nil {
			errs = append(errs, err)
		}
	}
	if err := removePins(dir); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		log.Warnw("tearing down pinned BPF objects", "generation", filepath.Base(dir), "error", err)
		return err
	}
	return nil
}

// emptyPinnedMap deletes every entry of the pinned map at path; an array's
// entries (which can't be deleted) are zeroed when zero.
func emptyPinnedMap(path string, zero bool) error {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()
	if zero {
		val := make([]byte, m.ValueSize())
		for i := uint32(0); i < m.MaxEntries(); i++ {
			if err := m.Update(i, val, ebpf.UpdateExist); err != nil {
				return err
			}
		}
		return nil
	}
	key := make([]byte, m.KeySize())
	for {
		if err := m.NextKey(nil, &key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			return err
		}
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
}

// teardownPins makes kloak's pinned BPF objects under root inert and
// removes them: the trampolines' slots are emptied first (every uprobe does
// nothing from then on), then the uprobes, the generations and the
// trampolines go. The virtual IP state (the hosts' fake IPs, the real
// addresses behind them) holds no secret and is kept for the next
// controller, unless uninstall, which removes the whole root.
func teardownPins(root string, uninstall bool, log *zap.SugaredLogger) error {
	var errs []error
	if m, err := ebpf.LoadPinnedMap(filepath.Join(root, "dispatch", "kloak_dispatch"), nil); err == nil {
		errs = append(errs, clearDispatch(m))
		_ = m.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	errs = append(errs, removePins(filepath.Join(root, "links")))
	gens, err := os.ReadDir(filepath.Join(root, "gens"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	for _, g := range gens {
		errs = append(errs, teardownGen(filepath.Join(root, "gens", g.Name()), log))
	}
	errs = append(errs, removePins(filepath.Join(root, "gens")), removePins(filepath.Join(root, "dispatch")))
	if err := os.Remove(filepath.Join(root, "meta")); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if uninstall {
		errs = append(errs, removePins(root))
	}
	return errors.Join(errs...)
}

// teardownKeptPins tears down, but for the virtual IP state, what a previous
// controller kept pinned under root, for a controller that does not keep
// its own (persistence off, or a pin root it can't keep them in): they would
// run next to its own, and patch each record a second time.
func teardownKeptPins(root string, log *zap.SugaredLogger) error {
	kept := false
	for _, d := range []string{"dispatch", "gens", "links"} {
		if fileExists(filepath.Join(root, d)) {
			kept = true
		}
	}
	if !kept {
		return nil
	}
	log.Infow("detaching the BPF objects a previous controller kept attached: this one does not keep them", "pinPath", root)
	return teardownPins(root, false, log)
}

// CleanupPins makes the BPF objects a kloak controller pinned under root
// inert and removes them, as an uninstall does: for a node whose controller
// could not do it (`kloak cleanup`). Call it with the node lock held, so no
// controller runs meanwhile.
func CleanupPins(root string, log *zap.SugaredLogger) error {
	if err := requireBPFFS(root); err != nil {
		return err
	}
	if !dirExists(root) {
		return nil
	}
	return teardownPins(root, true, log)
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
