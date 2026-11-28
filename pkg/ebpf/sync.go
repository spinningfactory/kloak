//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"golang.org/x/net/http2/hpack"

	"github.com/spinningfactory/kloak/pkg/logging"
	"github.com/spinningfactory/kloak/pkg/secrets"
)

// syncSecrets pulls a snapshot from the given secrets.Source and applies
// it to the secret store (secretStore.apply). The translation from a
// semantic secrets.Secret to the wire-format secretValue and chunks lives
// in secret_store.go; nothing there knows where the snapshot came from.
func syncSecrets(ctx context.Context, store *secretStore, source secrets.Source) error {
	if source == nil {
		return nil
	}

	snapshot, err := source.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshot secrets: %w", err)
	}
	_, err = store.apply(snapshot, time.Now())
	return err
}

// mapErrors collects the failed map operations of a sync, each logged where
// it fails, so that the sync can report that it has to be retried.
type mapErrors struct {
	n     int
	first error
}

func (e *mapErrors) add(err error) {
	if e.first == nil {
		e.first = err
	}
	e.n++
}

// err returns nil when no operation on the map name failed.
func (e *mapErrors) err(name string) error {
	if e.n == 0 {
		return nil
	}
	return fmt.Errorf("%s: %d failed map operations, the first: %w", name, e.n, e.first)
}

// errHuffmanKeyTooShort reports a placeholder whose HPACK-Huffman code is
// shorter than a secret_map key, so its HTTP/2 form cannot be looked up.
var errHuffmanKeyTooShort = errors.New("placeholder's Huffman code is shorter than a BPF key")

// huffmanEntry returns the secret_map entry of the HPACK-Huffman form of a
// placeholder, which HTTP/2 clients send in header fields: keyed by the first
// 8 bytes of Huffman(shadow), with Huffman(real) as its real. raw is the
// placeholder's own entry, whose host, IP and port restrictions it shares.
//
// The data plane patches the bytes Huffman(shadow) spans on the wire. Unless
// the code ends on a byte boundary, the last of them also holds the first
// bits of what follows the placeholder in the same string (the next
// character, or the string's EOS padding): PadBits counts them, and the patch
// leaves them unchanged (patch_delta in bpf/helpers.h). That is only sound
// when shadow and real have the same Huffman bit length, which the shadow
// generator guarantees: the string's length prefix on the wire is not
// rewritten, and what follows the placeholder must stay where it is. A pair
// that does not have it gets no entry, and its HTTP/2 form is sent as is.
func huffmanEntry(shadow, realValue string, raw *secretValue) (secretKey, secretValue, error) {
	e, err := huffmanStoreEntry(shadow, realValue, raw)
	return e.key, e.val, err
}

// huffmanStoreEntry is huffmanEntry's store entry: with its chunks, holding
// Huffman(shadow) and its delta to Huffman(real), PadBits low bits of the
// last byte left out of the delta.
func huffmanStoreEntry(shadow, realValue string, raw *secretValue) (storeEntry, error) {
	var key secretKey
	var val secretValue
	huffShadow := hpack.AppendHuffmanString(nil, shadow)
	bits := secrets.HuffmanBits(shadow)
	switch {
	case len(huffShadow) < len(key.Prefix):
		return storeEntry{}, errHuffmanKeyTooShort
	case bits != secrets.HuffmanBits(realValue):
		// The bit lengths are value-derived: keep them out of the error.
		return storeEntry{}, errors.New("shadow and real have different HPACK Huffman bit lengths")
	case len(huffShadow) > len(val.RealSecret):
		// TODO(kloak#383): real_secret goes with the phase-1 switchover;
		// the chunks take a code of any length.
		return storeEntry{}, fmt.Errorf("placeholder's Huffman code is longer than %d bytes", len(val.RealSecret))
	}
	copy(key.Prefix[:], huffShadow)

	// The same bit length, so the same byte length.
	huffReal := hpack.AppendHuffmanString(nil, realValue)
	val.Len = uint32(len(huffShadow))
	copy(val.RealSecret[:], huffReal)
	val.PadBits = uint8(len(huffShadow)*8 - bits)
	val.HostLen = raw.HostLen
	val.AllowedHost = raw.AllowedHost
	val.IpLen = raw.IpLen
	val.AllowedIp = raw.AllowedIp
	val.Port = raw.Port
	val.Protocol = raw.Protocol
	val.PrefixLen = uint32(copy(val.FullPrefix[:], huffShadow))
	return newStoreEntry(key, &val, huffShadow, huffReal, val.PadBits), nil
}

// syncSecretACL makes secret_acl hold exactly the entries the bindings grant
// over the snapshot: missing entries are added, the rest pruned (unless not
// prune: while adopting a previous controller's maps, whose entries are for
// pods not bound again yet). Pruning is what revokes a binding when a pod
// goes away, a container restarts with a new cgroup, or a secret's
// placeholder changes. Like applySecrets, it reports failed map operations
// once it has done the others.
func syncSecretACL(aclMap *ebpf.Map, snapshot []secrets.Secret, bindings map[string]podBinding, prune bool, log *zap.SugaredLogger) error {
	desired := secretACL(snapshot, bindings)
	var errs mapErrors

	var stale []secretACLKey
	present := make(map[secretACLKey]struct{}, len(desired))
	var k secretACLKey
	var v uint8
	iter := aclMap.Iterate()
	for iter.Next(&k, &v) {
		if _, ok := desired[k]; ok {
			present[k] = struct{}{}
		} else if prune {
			stale = append(stale, k)
		}
	}
	if err := iter.Err(); err != nil {
		log.Errorw("error iterating BPF secret_acl", "error", err)
		errs.add(err)
	}

	allowed := uint8(1)
	added := 0
	for key := range desired {
		if _, ok := present[key]; ok {
			continue
		}
		if err := aclMap.Update(&key, &allowed, ebpf.UpdateAny); err != nil {
			// A missing entry fails closed: the pod's placeholder is not rewritten.
			log.Errorw("failed to grant secret binding", "error", err, "cgroupID", key.CgroupID)
			errs.add(err)
			continue
		}
		added++
	}
	for i := range stale {
		if err := aclMap.Delete(&stale[i]); err != nil {
			log.Errorw("failed to revoke stale secret binding", "error", err, "cgroupID", stale[i].CgroupID)
			errs.add(err)
		}
	}

	logging.Tracew(log, "secret binding sync complete",
		"bindings", len(bindings), "entries", len(desired), "added", added, "pruned", len(stale))
	return errs.err("secret_acl")
}
