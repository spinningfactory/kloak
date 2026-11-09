//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"golang.org/x/net/http2/hpack"

	"github.com/spinningfactory/kloak/pkg/logging"
	"github.com/spinningfactory/kloak/pkg/secrets"
)

// syncSecrets pulls a snapshot from the given secrets.Source and applies
// it to the BPF secret_map. The translation
// from a semantic secrets.Secret to the wire-format secretValue lives
// here; nothing in this file knows where the snapshot came from.
//
// Behavior preserved verbatim from the previous source-coupled
// version of this function:
//   - upsert each (real, shadow) pair under the shadow's first 8 bytes
//   - emit an HPACK-Huffman variant for HTTP/2 interception
//   - prune BPF map entries that no longer appear in the snapshot
func syncSecrets(ctx context.Context, secretMap *ebpf.Map, source secrets.Source, log *zap.SugaredLogger) error {
	if source == nil {
		return nil
	}

	snapshot, err := source.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshot secrets: %w", err)
	}
	_, err = applySecrets(secretMap, snapshot, log)
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

// applySecrets writes a snapshot to secret_map (see syncSecrets) and returns
// the hostnames the synced secrets are restricted to, the watched hosts that
// get virtual IPs. Split out so the manager can reuse the same snapshot for
// the secret_acl and virtual IP syncs. A failed map operation does not stop
// the others: the error reports it once they are all done.
func applySecrets(secretMap *ebpf.Map, snapshot []secrets.Secret, log *zap.SugaredLogger) (map[string]struct{}, error) {
	// newKeys tracks which keys we upsert so we can prune stale entries afterwards.
	newKeys := make(map[secretKey]struct{})
	hostNames := make(map[string]struct{})
	var errs mapErrors

	for i := range snapshot {
		s := &snapshot[i]

		// The BPF filter treats host_len >= MAX_HOST_LEN (64) as
		// "no filter" (tls_uprobe.c: `val_host_len < MAX_HOST_LEN`).
		// If we synced a too-long host, the filter would be bypassed
		// and the secret rewritten on every destination — skip
		// instead so the app sends the shadow placeholder and the
		// real value stays protected in-kernel.
		if len(s.Host) >= len(secretValue{}.AllowedHost) {
			log.Errorw("allowed host exceeds maximum length, skipping sync (secret will not be rewritten)",
				"owner", s.OwnerID, "key", s.Key,
				"hostLen", len(s.Host), "max", len(secretValue{}.AllowedHost)-1)
			continue
		}

		// Minimum shadow length is enforced by the source; defensive
		// re-check so a misbehaving Source can't crash the sync.
		if len(s.Shadow) < secrets.ShadowPrefixLen {
			logging.Tracew(log, "skipping secret too short for BPF key",
				"owner", s.OwnerID, "key", s.Key, "len", len(s.Shadow))
			continue
		}

		var bpfKey secretKey
		copy(bpfKey.Prefix[:], s.Shadow[:secrets.ShadowPrefixLen])
		if _, exists := newKeys[bpfKey]; exists {
			log.Errorw("8-byte BPF key collision detected — two secrets share the same prefix, one will be shadowed",
				"owner", s.OwnerID, "key", s.Key, "prefix", s.Shadow[:secrets.ShadowPrefixLen])
		}
		newKeys[bpfKey] = struct{}{}

		var val secretValue
		val.Len = uint32(len(s.Real))
		if val.Len > 128 {
			logging.Tracew(log, "truncating secret value to max BPF size (128)",
				"owner", s.OwnerID, "key", s.Key)
			val.Len = 128
		}
		copy(val.RealSecret[:], s.Real[:val.Len])

		// Store the full prefix (up to 42 bytes) for post-lookup verification.
		prefixLen := len(s.Shadow)
		if prefixLen > 42 {
			prefixLen = 42
		}
		val.PrefixLen = uint32(prefixLen)
		copy(val.FullPrefix[:], s.Shadow[:prefixLen])

		// Set allowed host/IP for filtering.
		switch {
		case s.Host != "":
			val.HostLen = uint32(len(s.Host))
			copy(val.AllowedHost[:], s.Host)
			val.IpLen = 0 // Host-based filtering
			hostNames[s.Host] = struct{}{}
		case s.IP != nil:
			copy(val.AllowedIp[:], s.IP.To16())
			val.IpLen = 16 // IP-based filtering with valid IP
		default:
			// HostLen == 0 and IpLen == 0 means wildcard (allow all hosts/IPs)
			val.IpLen = 0
		}

		val.Port = s.Port
		val.Protocol = s.Protocol

		if err := secretMap.Update(&bpfKey, &val, 0); err != nil {
			log.Errorw("failed to update BPF secret_map", "error", err,
				"owner", s.OwnerID, "key", s.Key)
			errs.add(err)
		} else {
			logging.Tracew(log, "synced secret into eBPF map",
				"owner", s.OwnerID, "key", s.Key,
				"hostLen", val.HostLen, "port", val.Port, "protocol", val.Protocol)
		}

		// Also store the placeholder's HPACK-Huffman form, which HTTP/2
		// clients send in header fields (huffmanEntry).
		huffKey, huffVal, err := huffmanEntry(s.Shadow, s.Real, &val)
		_, taken := newKeys[huffKey]
		switch {
		case errors.Is(err, errHuffmanKeyTooShort):
			logging.Tracew(log, "no HTTP/2 Huffman variant: the placeholder's Huffman code is shorter than a BPF key",
				"owner", s.OwnerID, "key", s.Key)
		case err != nil:
			log.Warnw("no HTTP/2 Huffman variant, the placeholder will not be rewritten in HTTP/2 headers",
				"owner", s.OwnerID, "key", s.Key, "reason", err)
		case taken:
			// Another entry of this snapshot has the key: keep the first.
		default:
			newKeys[huffKey] = struct{}{}
			if err := secretMap.Update(&huffKey, &huffVal, 0); err != nil {
				log.Errorw("failed to update BPF secret_map (Huffman)", "error", err,
					"owner", s.OwnerID, "key", s.Key)
				errs.add(err)
			} else {
				logging.Tracew(log, "synced Huffman secret into eBPF map",
					"owner", s.OwnerID, "key", s.Key, "huffLen", huffVal.Len)
			}
		}
	}

	// Prune stale entries: iterate existing map keys and delete any not in newKeys.
	var staleKeys []secretKey
	var iterKey secretKey
	var iterVal secretValue
	iter := secretMap.Iterate()
	for iter.Next(&iterKey, &iterVal) {
		if _, exists := newKeys[iterKey]; !exists {
			staleKeys = append(staleKeys, iterKey)
		}
	}
	if err := iter.Err(); err != nil {
		log.Errorw("error iterating BPF secret_map for pruning", "error", err)
		errs.add(err)
	}
	for i := range staleKeys {
		if err := secretMap.Delete(&staleKeys[i]); err != nil {
			log.Errorw("failed to delete stale BPF secret_map entry", "error", err)
			errs.add(err)
		} else {
			logging.Tracew(log, "pruned stale entry from eBPF map")
		}
	}

	log.Debugw("secret sync complete",
		"snapshotEntries", len(snapshot), "bpfKeys", len(newKeys),
		"pruned", len(staleKeys), "watchedHosts", len(hostNames))
	return hostNames, errs.err("secret_map")
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
	var key secretKey
	var val secretValue
	huffShadow := hpack.AppendHuffmanString(nil, shadow)
	bits := secrets.HuffmanBits(shadow)
	switch {
	case len(huffShadow) < len(key.Prefix):
		return key, val, errHuffmanKeyTooShort
	case bits != secrets.HuffmanBits(realValue):
		// The bit lengths are value-derived: keep them out of the error.
		return key, val, errors.New("shadow and real have different HPACK Huffman bit lengths")
	case len(huffShadow) > len(val.RealSecret):
		return key, val, fmt.Errorf("placeholder's Huffman code is longer than %d bytes", len(val.RealSecret))
	}
	copy(key.Prefix[:], huffShadow)

	val.Len = uint32(len(huffShadow))
	copy(val.RealSecret[:], hpack.AppendHuffmanString(nil, realValue))
	val.PadBits = uint8(len(huffShadow)*8 - bits)
	val.HostLen = raw.HostLen
	val.AllowedHost = raw.AllowedHost
	val.IpLen = raw.IpLen
	val.AllowedIp = raw.AllowedIp
	val.Port = raw.Port
	val.Protocol = raw.Protocol
	val.PrefixLen = uint32(copy(val.FullPrefix[:], huffShadow))
	return key, val, nil
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
