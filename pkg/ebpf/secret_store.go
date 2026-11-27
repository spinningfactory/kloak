//go:build linux

package ebpf

// The secret store (spinningfactory/kloak#383): secret_map holds a
// placeholder's metadata, secret_chunks its placeholder and patch, in
// secretChunkLen-byte chunks of one generation (see struct secret_chunk in
// bpf/tls_uprobe.c). secretStore writes both from the secret source's
// snapshots so that a reader never sees a generation half written or gone
// while it may still use it:
//
//   - a new entry's chunks are all written before its secret_map entry;
//   - a changed entry (its placeholder or real value) gets a new generation,
//     whose chunks are all written before the secret_map entry is pointed at
//     it; the previous generation is deleted once secretStoreGrace has
//     passed. When the new generation can't be written (the store is full,
//     a map update fails), the entry is withdrawn from secret_map instead:
//     the store never rewrites a placeholder with a value the Secret no
//     longer holds (a rotated-out credential). A later sync writes it;
//   - an unchanged entry keeps its generation (the secret source is synced
//     on every Secret event, and every 5 min); its host, IP or port
//     restrictions are updated in place;
//   - a removed entry's secret_map entry goes first, its chunks after the
//     grace period.
//
// The chunks map is sized from a byte budget (SecretStoreConfig): an entry
// whose chunks don't fit is left out (its placeholder is not rewritten), and
// written by a later sync once the grace period has freed room
// (collectSecretStore). It is never written in part. An unchanged entry
// whose metadata update fails keeps its generation: its value still matches
// the Secret.
//
// With the data plane pinned (pins.go), the maps outlive the controller: the
// next controller of the build rebuilds the store's state from them
// (secretStore.rebuild).

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/spinningfactory/kloak/pkg/logging"
	"github.com/spinningfactory/kloak/pkg/secrets"
)

// secretChunkKey matches C struct secret_chunk_key.
type secretChunkKey struct {
	Key secretKey // the secret_map key
	Gen uint32    // secretValue.Gen of the entry
	Idx uint32    // chunk index: bytes [Idx*secretChunkLen, (Idx+1)*secretChunkLen)
}

// secretChunk matches C struct secret_chunk.
type secretChunk struct {
	Shadow [secretChunkLen]byte // the placeholder as on the wire
	Delta  [secretChunkLen]byte // Shadow XOR the real value as on the wire
}

// chunkCount is the number of chunks of an n-byte entry.
func chunkCount(n int) int {
	return (n + secretChunkLen - 1) / secretChunkLen
}

// patchTailMask is patch_tail_mask in bpf/helpers.h: the bits of a
// placeholder's last byte that are the placeholder's, padBits low bits being
// the start of what follows it.
func patchTailMask(padBits uint8) byte {
	return byte(0xff << (padBits & 7))
}

// The store's metrics, on the controller's metrics endpoint.
var (
	secretStoreCapacity = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kloak_secret_store_capacity_chunks",
		Help: "Chunks the node's secret store can hold (from --secret-store-bytes).",
	})
	secretStoreUsed = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kloak_secret_store_used_chunks",
		Help: "Chunks the node's secret store holds, including the previous generations of changed secrets during their grace period.",
	})
	secretStoreRefused = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kloak_secret_store_refused_entries",
		Help: "Secret entries the last sync left out of the data plane (their placeholders go out unchanged): full, the store had no room; too_long, the value is longer than --max-secret-length or the data plane takes.",
	}, []string{"reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(secretStoreCapacity, secretStoreUsed, secretStoreRefused)
}

// storeEntry is what the store holds for one secret_map key: the entry's
// value (whose Gen the store sets) and its chunks.
type storeEntry struct {
	key    secretKey
	val    secretValue
	chunks []secretChunk
	sum    [sha256.Size]byte // chunkSum
	// owner and name identify the secret in logs.
	owner, name string
}

// newStoreEntry returns the entry of a placeholder as on the wire, shadow,
// and the real value as on the wire, of the same length. padBits low bits
// of the last byte are what follows the placeholder: its delta leaves them.
func newStoreEntry(key secretKey, val *secretValue, shadow, real []byte, padBits uint8) storeEntry {
	e := storeEntry{key: key, val: *val, chunks: make([]secretChunk, chunkCount(len(shadow)))}
	for i := range shadow {
		c := &e.chunks[i/secretChunkLen]
		c.Shadow[i%secretChunkLen] = shadow[i]
		c.Delta[i%secretChunkLen] = shadow[i] ^ real[i]
	}
	if n := len(shadow); n > 0 {
		e.chunks[(n-1)/secretChunkLen].Delta[(n-1)%secretChunkLen] &= patchTailMask(padBits)
	}
	e.sum = chunkSum(uint32(len(shadow)), e.chunks)
	return e
}

// chunkSum identifies the content of an n-byte entry's chunks, so that a
// sync tells an unchanged entry from a changed one without reading its
// chunks back.
func chunkSum(n uint32, chunks []secretChunk) [sha256.Size]byte {
	h := sha256.New()
	_ = binary.Write(h, binary.LittleEndian, n)
	for i := range chunks {
		h.Write(chunks[i].Shadow[:])
		h.Write(chunks[i].Delta[:])
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// storedEntry is a secret_map entry the store wrote (or found at start).
type storedEntry struct {
	gen    uint32
	chunks int               // chunk indexes 0 .. chunks-1 of gen
	sum    [sha256.Size]byte // chunkSum of them
	// valid: its chunks were read back whole at start, or written; one that
	// is not gets a new generation at the next sync.
	valid bool
}

// retiredGen is a generation no secret_map entry points at, deleted once
// due.
type retiredGen struct {
	key    secretKey
	gen    uint32
	chunks int // chunk indexes 0 .. chunks-1
	from   int // the first not deleted yet
	due    time.Time
}

// secretStore writes the secrets of a snapshot to secret_map and
// secret_chunks (see the top of this file). Safe for concurrent use.
type secretStore struct {
	mu       sync.Mutex
	secrets  *ebpf.Map // secret_map
	chunks   *ebpf.Map // secret_chunks
	maxLen   int       // the longest value synced (SecretStoreConfig.maxLen)
	capacity int       // secret_chunks' max_entries
	log      *zap.SugaredLogger

	entries map[secretKey]storedEntry // what secret_map holds
	retired []retiredGen
	// used counts the chunk indexes of the entries and retired generations:
	// at least what secret_chunks holds.
	used    int
	lastGen uint32 // the generation last handed out
	// refusedFull and refusedTooLong count the entries the last apply left
	// out for want of room, and the secrets it left out for their length.
	refusedFull, refusedTooLong int
}

func newSecretStore(secretMap, chunks *ebpf.Map, maxLen int, log *zap.SugaredLogger) *secretStore {
	s := &secretStore{
		secrets:  secretMap,
		chunks:   chunks,
		maxLen:   maxLen,
		capacity: int(chunks.MaxEntries()),
		log:      log,
		entries:  make(map[secretKey]storedEntry),
	}
	s.report()
	return s
}

// report updates the store's metrics.
func (s *secretStore) report() {
	secretStoreCapacity.Set(float64(s.capacity))
	secretStoreUsed.Set(float64(s.used))
	secretStoreRefused.WithLabelValues("full").Set(float64(s.refusedFull))
	secretStoreRefused.WithLabelValues("too_long").Set(float64(s.refusedTooLong))
}

// nextGen hands out a generation, never 0 (no chunks, for the data plane).
func (s *secretStore) nextGen() uint32 {
	s.lastGen++
	if s.lastGen == 0 {
		s.lastGen = 1
	}
	return s.lastGen
}

// rebuild reads the store's state back from the maps a previous controller
// left (pinned): every secret_map entry, with its generation's chunks read
// back to tell whether a sync changes it; and the generations of
// secret_chunks no entry points at, which are deleted after a grace period
// from now (when they were retired is not known). An entry whose chunks are
// not all there is rewritten by the next sync.
func (s *secretStore) rebuild(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := make(map[secretKey]storedEntry)
	lens := make(map[secretKey]uint32)
	var k secretKey
	var v secretValue
	iter := s.secrets.Iterate()
	for iter.Next(&k, &v) {
		entries[k] = storedEntry{gen: v.Gen, chunks: chunkCount(int(v.Len))}
		lens[k] = v.Len
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("reading secret_map: %w", err)
	}

	type genKey struct {
		key secretKey
		gen uint32
	}
	type genChunks struct{ count, end int } // chunks found, highest index + 1
	found := make(map[genKey]genChunks)
	var ck secretChunkKey
	var c secretChunk
	citer := s.chunks.Iterate()
	for citer.Next(&ck, &c) {
		g := genKey{ck.Key, ck.Gen}
		f := found[g]
		f.count++
		f.end = max(f.end, int(ck.Idx)+1)
		found[g] = f
	}
	if err := citer.Err(); err != nil {
		return fmt.Errorf("reading secret_chunks: %w", err)
	}

	var lastGen uint32
	used := 0
	var retired []retiredGen
	for g, f := range found {
		lastGen = max(lastGen, g.gen)
		if e, ok := entries[g.key]; ok && e.gen == g.gen {
			continue
		}
		retired = append(retired, retiredGen{key: g.key, gen: g.gen, chunks: f.end, due: now.Add(secretStoreGrace)})
		used += f.end
	}
	for key, e := range entries {
		lastGen = max(lastGen, e.gen)
		f := found[genKey{key, e.gen}]
		if e.gen != 0 && f.count == e.chunks && f.end == e.chunks {
			chunks := make([]secretChunk, e.chunks)
			e.valid = true
			for i := range chunks {
				if err := s.chunks.Lookup(&secretChunkKey{Key: key, Gen: e.gen, Idx: uint32(i)}, &chunks[i]); err != nil {
					e.valid = false
					break
				}
			}
			if e.valid {
				e.sum = chunkSum(lens[key], chunks)
			}
		}
		// The chunks to delete with it are whatever its generation has.
		e.chunks = max(e.chunks, f.end)
		used += e.chunks
		entries[key] = e
	}
	s.entries, s.retired, s.used, s.lastGen = entries, retired, used, lastGen
	s.report()
	s.log.Infow("secret store: adopted the pinned secrets",
		"entries", len(entries), "retiredGenerations", len(retired), "usedChunks", used, "capacityChunks", s.capacity)
	return nil
}

// apply makes the maps hold the snapshot's secrets (see the top of this
// file), and returns the hostnames they are restricted to, the watched hosts
// that get virtual IPs. Generations due are deleted first. A failed map
// operation does not stop the others: the error reports them once they are
// all done, and a retry completes the maps.
func (s *secretStore) apply(snapshot []secrets.Secret, now time.Time) (map[string]struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs mapErrors
	s.collectLocked(now, &errs)

	// A generation is retired when its secret_map entry has been changed or
	// deleted: the grace period runs from then, which is now plus the time
	// this sync has taken (writing a large store's chunks takes a while),
	// not from the sync's start.
	start := time.Now()
	due := func() time.Time { return now.Add(time.Since(start) + secretStoreGrace) }

	want, hosts, tooLong := s.desired(snapshot)
	full := 0
	written := 0
	for _, e := range want {
		key := e.key
		cur, ok := s.entries[key]
		if ok && cur.valid && cur.sum == e.sum {
			// Unchanged: its restrictions may have changed, in place.
			e.val.Gen = cur.gen
			if err := s.secrets.Update(&key, &e.val, ebpf.UpdateAny); err != nil {
				s.log.Errorw("failed to update BPF secret_map", "error", err, "owner", e.owner, "key", e.name)
				errs.add(err)
			}
			continue
		}
		// A changed entry whose new generation can't be published is
		// withdrawn: its previous generation would rewrite the placeholder
		// with a value the Secret no longer holds (a rotated-out
		// credential). The next sync writes it.
		n := len(e.chunks)
		if s.used+n > s.capacity {
			full++
			s.log.Errorw("secret store full: secret left out of the data plane, its placeholder is not rewritten until there is room (raise controller.ebpf.secretStoreBytes)",
				"owner", e.owner, "key", e.name, "changed", ok, "chunks", n,
				"usedChunks", s.used, "capacityChunks", s.capacity)
			if ok {
				s.withdraw(key, cur, due(), &errs)
			}
			continue
		}
		gen, err := s.writeChunks(key, e.chunks, now)
		if err != nil {
			s.log.Errorw("failed to write the secret's chunks, the secret is not rewritten",
				"error", err, "owner", e.owner, "key", e.name, "changed", ok)
			errs.add(err)
			if ok {
				s.withdraw(key, cur, due(), &errs)
			}
			continue
		}
		e.val.Gen = gen
		if err := s.secrets.Update(&key, &e.val, ebpf.UpdateAny); err != nil {
			s.log.Errorw("failed to update BPF secret_map, the secret is not rewritten", "error", err,
				"owner", e.owner, "key", e.name, "changed", ok)
			errs.add(err)
			// Nothing refers to the new generation.
			s.retire(key, gen, n, now)
			if ok {
				s.withdraw(key, cur, due(), &errs)
			}
			continue
		}
		if ok {
			s.retire(key, cur.gen, cur.chunks, due())
		}
		s.entries[key] = storedEntry{gen: gen, chunks: n, sum: e.sum, valid: true}
		written++
		logging.Tracew(s.log, "synced secret into eBPF map",
			"owner", e.owner, "key", e.name, "gen", gen, "chunks", n,
			"hostLen", e.val.HostLen, "port", e.val.Port, "protocol", e.val.Protocol)
	}

	// Prune the entries no longer in the snapshot: secret_map first, their
	// chunks once the grace period has passed.
	wanted := make(map[secretKey]struct{}, len(want))
	for i := range want {
		wanted[want[i].key] = struct{}{}
	}
	var stale []secretKey
	var staleVals []secretValue
	var k secretKey
	var v secretValue
	iter := s.secrets.Iterate()
	for iter.Next(&k, &v) {
		if _, ok := wanted[k]; !ok {
			stale = append(stale, k)
			staleVals = append(staleVals, v)
		}
	}
	if err := iter.Err(); err != nil {
		s.log.Errorw("error iterating BPF secret_map for pruning", "error", err)
		errs.add(err)
	}
	for i := range stale {
		if err := s.secrets.Delete(&stale[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			s.log.Errorw("failed to delete stale BPF secret_map entry", "error", err)
			errs.add(err)
			continue
		}
		if e, ok := s.entries[stale[i]]; ok {
			delete(s.entries, stale[i])
			s.retire(stale[i], e.gen, e.chunks, due())
		} else if gen := staleVals[i].Gen; gen != 0 {
			// Not one this store wrote or found at start: its chunks are
			// counted from now.
			n := chunkCount(int(staleVals[i].Len))
			s.used += n
			s.retire(stale[i], gen, n, due())
		}
		logging.Tracew(s.log, "pruned stale entry from eBPF map")
	}

	s.refusedFull, s.refusedTooLong = full, tooLong
	s.report()
	s.log.Debugw("secret sync complete",
		"snapshotEntries", len(snapshot), "bpfKeys", len(want), "written", written,
		"pruned", len(stale), "watchedHosts", len(hosts),
		"usedChunks", s.used, "capacityChunks", s.capacity, "retiredGenerations", len(s.retired),
		"refusedFull", full, "refusedTooLong", tooLong)
	return hosts, errs.err("secret store")
}

// desired returns the store entries of a snapshot, in its order: each
// secret's placeholder entry and its HPACK-Huffman entry (huffmanEntry), the
// hostnames they are restricted to, and how many secrets were left out for
// their length. A secret the data plane can't take is left out, and logged:
// its placeholder goes out unchanged.
func (s *secretStore) desired(snapshot []secrets.Secret) (want []storeEntry, hosts map[string]struct{}, tooLong int) {
	hosts = make(map[string]struct{})
	at := make(map[secretKey]int)
	for i := range snapshot {
		sec := &snapshot[i]

		// The BPF filter treats host_len >= MAX_HOST_LEN (64) as
		// "no filter" (tls_uprobe.c: `val_host_len < MAX_HOST_LEN`).
		// If we synced a too-long host, the filter would be bypassed
		// and the secret rewritten on every destination — skip
		// instead so the app sends the shadow placeholder and the
		// real value stays protected in-kernel.
		if len(sec.Host) >= len(secretValue{}.AllowedHost) {
			s.log.Errorw("allowed host exceeds maximum length, skipping sync (secret will not be rewritten)",
				"owner", sec.OwnerID, "key", sec.Key,
				"hostLen", len(sec.Host), "max", len(secretValue{}.AllowedHost)-1)
			continue
		}
		// Minimum shadow length is enforced by the source; defensive
		// re-check so a misbehaving Source can't crash the sync.
		if len(sec.Shadow) < secrets.ShadowPrefixLen {
			logging.Tracew(s.log, "skipping secret too short for BPF key",
				"owner", sec.OwnerID, "key", sec.Key, "len", len(sec.Shadow))
			continue
		}
		// Never a truncated rewrite: the webhook refuses such a value at
		// admission, but a Secret admitted before (or with a larger
		// --max-secret-length) still reaches the sync.
		if len(sec.Real) > s.maxLen {
			tooLong++
			s.log.Errorw("secret value longer than the maximum, skipping sync (secret will not be rewritten)",
				"owner", sec.OwnerID, "key", sec.Key, "len", len(sec.Real), "max", s.maxLen)
			continue
		}
		// The patch turns the placeholder's bytes into the real value's:
		// the shadow generator makes them the same length. They differ
		// only while a changed Secret's shadow has yet to be generated
		// again: a rewrite would corrupt what follows the placeholder.
		if len(sec.Shadow) != len(sec.Real) {
			s.log.Errorw("placeholder and secret value differ in length, skipping sync (secret will not be rewritten until its shadow is regenerated)",
				"owner", sec.OwnerID, "key", sec.Key, "shadowLen", len(sec.Shadow), "len", len(sec.Real))
			continue
		}

		raw := rawEntry(sec)
		if j, exists := at[raw.key]; exists {
			s.log.Errorw("8-byte BPF key collision detected — two secrets share the same prefix, one will be shadowed",
				"owner", sec.OwnerID, "key", sec.Key, "prefix", sec.Shadow[:secrets.ShadowPrefixLen])
			want[j] = raw
		} else {
			at[raw.key] = len(want)
			want = append(want, raw)
		}
		if sec.Host != "" {
			hosts[sec.Host] = struct{}{}
		}

		// Also store the placeholder's HPACK-Huffman form, which HTTP/2
		// clients send in header fields (huffmanEntry).
		huff, err := huffmanStoreEntry(sec.Shadow, sec.Real, &raw.val)
		_, taken := at[huff.key]
		switch {
		case errors.Is(err, errHuffmanKeyTooShort):
			logging.Tracew(s.log, "no HTTP/2 Huffman variant: the placeholder's Huffman code is shorter than a BPF key",
				"owner", sec.OwnerID, "key", sec.Key)
		case err != nil:
			s.log.Warnw("no HTTP/2 Huffman variant, the placeholder will not be rewritten in HTTP/2 headers",
				"owner", sec.OwnerID, "key", sec.Key, "reason", err)
		case taken:
			// Another entry of this snapshot has the key: keep the first.
		default:
			huff.owner, huff.name = sec.OwnerID, sec.Key
			at[huff.key] = len(want)
			want = append(want, huff)
		}
	}
	return want, hosts, tooLong
}

// rawEntry returns the store entry of a secret's placeholder, as the
// application writes it. desired checked its lengths.
func rawEntry(sec *secrets.Secret) storeEntry {
	var key secretKey
	copy(key.Prefix[:], sec.Shadow[:secrets.ShadowPrefixLen])

	var val secretValue
	val.Len = uint32(len(sec.Real))
	// TODO(kloak#383): real_secret goes with the phase-1 switchover to the
	// chunks; until then secrets.DataPlaneMaxLen (the longest value synced)
	// is its size.
	copy(val.RealSecret[:], sec.Real)

	// Store the full prefix (up to 42 bytes) for post-lookup verification.
	val.PrefixLen = uint32(copy(val.FullPrefix[:], sec.Shadow))

	// Set allowed host/IP for filtering.
	switch {
	case sec.Host != "":
		val.HostLen = uint32(len(sec.Host))
		copy(val.AllowedHost[:], sec.Host)
		val.IpLen = 0 // Host-based filtering
	case sec.IP != nil:
		copy(val.AllowedIp[:], sec.IP.To16())
		val.IpLen = 16 // IP-based filtering with valid IP
	default:
		// HostLen == 0 and IpLen == 0 means wildcard (allow all hosts/IPs)
		val.IpLen = 0
	}
	val.Port = sec.Port
	val.Protocol = sec.Protocol

	e := newStoreEntry(key, &val, []byte(sec.Shadow), []byte(sec.Real), 0)
	e.owner, e.name = sec.OwnerID, sec.Key
	return e
}

// withdraw deletes key's secret_map entry, whose generation cur no longer
// holds the Secret's value, and retires that generation until due. A failure
// leaves the entry in place: the sync reports it, and its retry withdraws it.
func (s *secretStore) withdraw(key secretKey, cur storedEntry, due time.Time, errs *mapErrors) {
	if err := s.secrets.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		s.log.Errorw("failed to withdraw a changed secret from BPF secret_map: its previous value is still rewritten", "error", err)
		errs.add(err)
		return
	}
	delete(s.entries, key)
	s.retire(key, cur.gen, cur.chunks, due)
}

// writeChunks writes chunks as a new generation of key, and returns it.
// What a failure leaves written of it is deleted by the next collection:
// nothing refers to it.
func (s *secretStore) writeChunks(key secretKey, chunks []secretChunk, now time.Time) (uint32, error) {
	gen := s.nextGen()
	for i := range chunks {
		ck := secretChunkKey{Key: key, Gen: gen, Idx: uint32(i)}
		if err := s.chunks.Update(&ck, &chunks[i], ebpf.UpdateNoExist); err != nil {
			s.used += i
			s.retire(key, gen, i, now)
			return 0, fmt.Errorf("writing chunk %d of %d to secret_chunks: %w", i, len(chunks), err)
		}
	}
	s.used += len(chunks)
	return gen, nil
}

// retire records chunk indexes 0 .. chunks-1 of key's generation gen, which
// no secret_map entry points at any more, to be deleted once due. They stay
// in used until then.
func (s *secretStore) retire(key secretKey, gen uint32, chunks int, due time.Time) {
	if chunks > 0 {
		s.retired = append(s.retired, retiredGen{key: key, gen: gen, chunks: chunks, due: due})
	}
}

// collect deletes the retired generations that are due, and reports how
// many chunks it freed, and whether the last apply left entries out for want
// of room (which the freed chunks may now hold: the caller syncs again).
func (s *secretStore) collect(now time.Time) (freed int, refusedFull bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs mapErrors
	freed = s.collectLocked(now, &errs)
	if freed > 0 {
		s.report()
	}
	return freed, s.refusedFull > 0, errs.err("secret_chunks")
}

func (s *secretStore) collectLocked(now time.Time, errs *mapErrors) (freed int) {
	kept := s.retired[:0]
	for _, r := range s.retired {
		if now.Before(r.due) {
			kept = append(kept, r)
			continue
		}
		for ; r.from < r.chunks; r.from++ {
			ck := secretChunkKey{Key: r.key, Gen: r.gen, Idx: uint32(r.from)}
			if err := s.chunks.Delete(&ck); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				s.log.Errorw("failed to delete a retired generation of a secret from secret_chunks", "error", err)
				errs.add(err)
				break
			}
		}
		if r.from < r.chunks {
			kept = append(kept, r)
			continue
		}
		s.used -= r.chunks
		freed += r.chunks
	}
	s.retired = kept
	return freed
}

// empty deletes every entry of both maps (an uninstall): the real secrets
// leave the kernel.
func (s *secretStore) empty() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := errors.Join(emptyMap(s.secrets), emptyMap(s.chunks))
	s.entries = make(map[secretKey]storedEntry)
	s.retired = nil
	s.used = 0
	s.report()
	return err
}

// collectSecretStore deletes the secret store's retired generations that are
// due, and syncs the secrets again when the last sync left some out for want
// of room: the freed chunks may hold them now.
func (m *TLSUprobeManager) collectSecretStore(ctx context.Context) {
	if m.store == nil || m.stopped.Load() {
		return
	}
	freed, refused, err := m.store.collect(time.Now())
	if err != nil {
		m.log.Warnw("deleting the secret store's retired generations; retried at the next sweep", "error", err)
	}
	if freed == 0 || !refused {
		return
	}
	if err := m.SyncSecrets(ctx); err != nil {
		m.log.Warnw("syncing the secrets the store had no room for", "error", err)
	}
}
