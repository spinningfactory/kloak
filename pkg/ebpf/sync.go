package ebpf

import (
	"context"
	"strings"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"golang.org/x/net/http2/hpack"

	"github.com/spinningfactory/kloak/pkg/storage"
)

func syncSecrets(secretMap, watchedHostsMap *ebpf.Map, store storage.Storage, log *zap.SugaredLogger) error {
	secrets, err := store.List(context.Background())
	if err != nil {
		return err
	}

	// newKeys tracks which keys we upsert so we can prune stale entries afterwards.
	newKeys := make(map[secretKey]struct{}, len(secrets))
	// newHosts tracks unique hostnames to sync to watched_hosts map.
	newHosts := make(map[watchedHostKey]struct{})

	for hash, entry := range secrets {
		// hash is already the full shadow value like "kloak:0a6dbc80-b38a-47"
		shadowPrefix := hash

		// Adjust length to match exactly, as the secret_reconciler does
		if len(shadowPrefix) > len(entry.Value) {
			shadowPrefix = shadowPrefix[:len(entry.Value)]
		} else if len(shadowPrefix) < len(entry.Value) {
			shadowPrefix += strings.Repeat(" ", len(entry.Value)-len(shadowPrefix))
		}

		// The BPF program looks up the first 8 bytes.
		// Minimum secret size is 8 bytes (kloak: + 2 UUID chars).
		if len(shadowPrefix) < 8 {
			log.Debugw("Skipping secret too short for BPF key", "hash", hash, "len", len(shadowPrefix))
			continue
		}

		var key secretKey
		copy(key.Prefix[:], []byte(shadowPrefix)[:8])
		if _, exists := newKeys[key]; exists {
			log.Errorw("8-byte BPF key collision detected — two secrets share the same prefix, one will be shadowed", "hash", hash, "prefix", shadowPrefix[:8])
		}
		newKeys[key] = struct{}{}

		var val secretValue
		val.Len = uint32(len(entry.Value))
		if val.Len > 128 {
			log.Debugw("Truncating secret value to max BPF size (128)", "hash", hash)
			val.Len = 128
		}
		copy(val.RealSecret[:], []byte(entry.Value)[:val.Len])

		// Store the full prefix (up to 42 bytes) for post-lookup verification.
		prefixLen := len(shadowPrefix)
		if prefixLen > 42 {
			prefixLen = 42
		}
		val.PrefixLen = uint32(prefixLen)
		copy(val.FullPrefix[:], []byte(shadowPrefix)[:prefixLen])

		// Set allowed host for host-based filtering
		if len(entry.AllowedHosts) > 0 && entry.AllowedHosts[0] != "*" {
			host := entry.AllowedHosts[0]
			if len(host) > len(val.AllowedHost) {
				host = host[:len(val.AllowedHost)]
			}
			val.HostLen = uint32(len(host))
			copy(val.AllowedHost[:], host)

			// Track this hostname for the watched_hosts map
			var whk watchedHostKey
			copy(whk.Host[:], host)
			newHosts[whk] = struct{}{}
		}
		// HostLen == 0 means wildcard (allow all hosts)

		// Set allowed port for port-based filtering
		// Port == 0 means wildcard (allow all ports)
		val.Port = entry.Port
		val.Protocol = entry.Protocol

		if err := secretMap.Update(&key, &val, 0); err != nil {
			log.Errorw("failed to update BPF secret_map", "error", err, "hash", hash)
		} else {
			log.Debugw("Synced secret into eBPF map", "hash", hash, "hostLen", val.HostLen, "port", val.Port, "protocol", val.Protocol)
		}

		// Also store a Huffman-encoded variant for HTTP/2 HPACK interception.
		// HPACK uses a static Huffman table (RFC 7541) so the encoding is
		// deterministic. The eBPF scanner checks for both plaintext "kloak:"
		// and its Huffman encoding (0xeb 0x41 0xc7 0xd6).
		//
		// Store a Huffman-encoded variant for HTTP/2 HPACK interception.
		// The rewritten Huffman data must be EXACTLY the same length as the
		// shadow's Huffman encoding — the HPACK length prefix in the wire
		// buffer is immutable. If the real's Huffman is longer, we skip
		// (HTTP/1.1 path still works). If shorter, pad with EOS (0xFF).
		huffShadow := hpack.AppendHuffmanString(nil, shadowPrefix)
		huffReal := hpack.AppendHuffmanString(nil, entry.Value)
		realHuffLen := len(huffReal)

		if len(huffShadow) >= 8 && realHuffLen > 0 {
			// Pad real with HPACK EOS bits to match shadow's Huffman length
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
				huffVal.Port = val.Port
				huffVal.Protocol = val.Protocol
				huffPrefixLen := len(huffShadow)
				if huffPrefixLen > 42 {
					huffPrefixLen = 42
				}
				huffVal.PrefixLen = uint32(huffPrefixLen)
				copy(huffVal.FullPrefix[:], huffShadow[:huffPrefixLen])

				if err := secretMap.Update(&huffKey, &huffVal, 0); err != nil {
					log.Errorw("failed to update BPF secret_map (Huffman)", "error", err, "hash", hash)
				} else {
					log.Debugw("Synced Huffman secret into eBPF map", "hash", hash, "huffLen", huffLen)
				}
			}
		} else if len(huffShadow) >= 8 && realHuffLen > len(huffShadow) {
			// This should not happen if the secret reconciler generates shadows
			// with sufficient Huffman length, but log it just in case.
			log.Debugw("Skipping HTTP/2 Huffman variant — shadow Huffman too short",
				"hash", hash, "shadowHuffLen", len(huffShadow), "realHuffLen", realHuffLen)
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
			log.Debugw("Pruned stale entry from eBPF map")
		}
	}

	// Sync watched_hosts map: add new hosts, prune stale ones.
	if watchedHostsMap != nil {
		syncWatchedHosts(watchedHostsMap, newHosts, log)
	}

	return nil
}

// syncWatchedHosts updates the watched_hosts BPF map with the given set of
// hostnames. Adds missing entries and removes stale ones.
func syncWatchedHosts(watchedHostsMap *ebpf.Map, newHosts map[watchedHostKey]struct{}, log *zap.SugaredLogger) {
	// Add all current hosts
	val := uint8(1)
	for host := range newHosts {
		if err := watchedHostsMap.Update(&host, &val, 0); err != nil {
			log.Errorw("failed to update watched_hosts map", "error", err, "host", string(host.Host[:]))
		}
	}

	// Prune stale hosts
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
			log.Debugw("Pruned stale watched host")
		}
	}
}
