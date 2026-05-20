//go:build linux

package ebpf

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"golang.org/x/net/http2/hpack"

	"github.com/spinningfactory/kloak/pkg/logging"
	"github.com/spinningfactory/kloak/pkg/secrets"
)

// syncSecrets pulls a snapshot from the given secrets.Source and applies
// it to the BPF secret_map (and the watched_hosts map). The translation
// from a semantic secrets.Secret to the wire-format secretValue lives
// here; nothing in this file knows where the snapshot came from.
//
// Behavior preserved verbatim from the previous source-coupled
// version of this function:
//   - upsert each (real, shadow) pair under the shadow's first 8 bytes
//   - emit an HPACK-Huffman variant for HTTP/2 interception
//   - prune BPF map entries that no longer appear in the snapshot
//   - sync the watched_hosts map for DNS-verified host filtering
func syncSecrets(ctx context.Context, secretMap, watchedHostsMap *ebpf.Map, source secrets.Source, log *zap.SugaredLogger) error {
	if source == nil {
		return nil
	}

	snapshot, err := source.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshot secrets: %w", err)
	}

	// newKeys tracks which keys we upsert so we can prune stale entries afterwards.
	newKeys := make(map[secretKey]struct{})
	// newHosts tracks unique hostnames to sync to the watched_hosts map.
	newHosts := make(map[watchedHostKey]struct{})

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

			var whk watchedHostKey
			copy(whk.Host[:], s.Host)
			newHosts[whk] = struct{}{}
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
		} else {
			logging.Tracew(log, "synced secret into eBPF map",
				"owner", s.OwnerID, "key", s.Key,
				"hostLen", val.HostLen, "port", val.Port, "protocol", val.Protocol)
		}

		// Also store a Huffman-encoded variant for HTTP/2 HPACK interception.
		// HPACK uses a static Huffman table (RFC 7541) so the encoding is
		// deterministic. The eBPF scanner checks for both plaintext "kl::"
		// and its Huffman encoding (0xeb 0x41 0xc7 0xd6).
		//
		// The rewritten Huffman data must be EXACTLY the same length as the
		// shadow's Huffman encoding — the HPACK length prefix in the wire
		// buffer is immutable. If the real's Huffman is longer, we skip
		// (HTTP/1.1 path still works). If shorter, pad with EOS (0xFF).
		huffShadow := hpack.AppendHuffmanString(nil, s.Shadow)
		huffReal := hpack.AppendHuffmanString(nil, s.Real)
		realHuffLen := len(huffReal)

		if len(huffShadow) >= 8 && realHuffLen > 0 && realHuffLen <= len(huffShadow) {
			// Pad real with HPACK EOS bits to match shadow's Huffman length.
			// realHuffLen <= len(huffShadow) is required: the wire-buffer
			// HPACK length prefix is shadow-sized and immutable, so a longer
			// Huffman blob would overflow it. The else-if below catches the
			// "too-long" case explicitly.
			for len(huffReal) < len(huffShadow) {
				huffReal = append(huffReal, 0xff)
			}

			var huffKey secretKey
			copy(huffKey.Prefix[:], huffShadow[:8])
			if _, exists := newKeys[huffKey]; !exists {
				newKeys[huffKey] = struct{}{}

				var huffVal secretValue
				huffLen := len(huffReal)
				if huffLen > 128 {
					huffLen = 128
				}
				huffVal.Len = uint32(huffLen)
				copy(huffVal.RealSecret[:], huffReal[:huffLen])
				huffVal.HostLen = val.HostLen
				huffVal.AllowedHost = val.AllowedHost
				huffVal.IpLen = val.IpLen
				copy(huffVal.AllowedIp[:], val.AllowedIp[:])
				huffVal.Port = val.Port
				huffVal.Protocol = val.Protocol
				huffPrefixLen := len(huffShadow)
				if huffPrefixLen > 42 {
					huffPrefixLen = 42
				}
				huffVal.PrefixLen = uint32(huffPrefixLen)
				copy(huffVal.FullPrefix[:], huffShadow[:huffPrefixLen])

				if err := secretMap.Update(&huffKey, &huffVal, 0); err != nil {
					log.Errorw("failed to update BPF secret_map (Huffman)", "error", err,
						"owner", s.OwnerID, "key", s.Key)
				} else {
					logging.Tracew(log, "synced Huffman secret into eBPF map",
						"owner", s.OwnerID, "key", s.Key, "huffLen", huffLen)
				}
			}
		} else if len(huffShadow) >= 8 && realHuffLen > len(huffShadow) {
			// This should not happen if the source generates shadows
			// with sufficient Huffman length, but log it just in case.
			logging.Tracew(log, "skipping HTTP/2 Huffman variant — shadow Huffman too short",
				"owner", s.OwnerID, "key", s.Key,
				"shadowHuffLen", len(huffShadow), "realHuffLen", realHuffLen)
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
	}
	for i := range staleKeys {
		if err := secretMap.Delete(&staleKeys[i]); err != nil {
			log.Errorw("failed to delete stale BPF secret_map entry", "error", err)
		} else {
			logging.Tracew(log, "pruned stale entry from eBPF map")
		}
	}

	// Sync watched_hosts map: add new hosts, prune stale ones.
	if watchedHostsMap != nil {
		syncWatchedHosts(watchedHostsMap, newHosts, log)
	}

	log.Debugw("secret sync complete",
		"snapshotEntries", len(snapshot), "bpfKeys", len(newKeys),
		"pruned", len(staleKeys), "watchedHosts", len(newHosts))

	return nil
}

// syncWatchedHosts updates the watched_hosts BPF map with the given set of
// hostnames. Adds missing entries and removes stale ones.
func syncWatchedHosts(watchedHostsMap *ebpf.Map, newHosts map[watchedHostKey]struct{}, log *zap.SugaredLogger) {
	val := uint8(1)
	for host := range newHosts {
		if err := watchedHostsMap.Update(&host, &val, 0); err != nil {
			log.Errorw("failed to update watched_hosts map", "error", err, "host", string(host.Host[:]))
		}
	}

	var staleHosts []watchedHostKey
	var iterHost watchedHostKey
	var iterVal uint8
	iter := watchedHostsMap.Iterate()
	for iter.Next(&iterHost, &iterVal) {
		if _, exists := newHosts[iterHost]; !exists {
			staleHosts = append(staleHosts, iterHost)
		}
	}
	if err := iter.Err(); err != nil {
		log.Errorw("error iterating watched_hosts map for pruning", "error", err)
	}
	for i := range staleHosts {
		if err := watchedHostsMap.Delete(&staleHosts[i]); err != nil {
			log.Errorw("failed to delete stale watched_hosts entry", "error", err)
		} else {
			logging.Tracew(log, "pruned stale watched host")
		}
	}
}
