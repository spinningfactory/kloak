package ebpf

import (
	"context"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"

	"github.com/spinningfactory/kloak/pkg/storage"
)

// syncSecrets updates a BPF secret_map with the latest shadow secret values
// from the given storage. Returns the set of keys that were synced and any
// stale keys that were pruned.
func syncSecrets(secretMap *ebpf.Map, store storage.Storage, log logr.Logger) error {
	secrets, err := store.List(context.Background())
	if err != nil {
		return err
	}

	// newKeys tracks which keys we upsert so we can prune stale entries afterwards.
	newKeys := make(map[secretKey]struct{}, len(secrets))

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
			log.V(1).Info("Skipping secret too short for BPF key", "hash", hash, "len", len(shadowPrefix))
			continue
		}

		var key secretKey
		copy(key.Prefix[:], []byte(shadowPrefix)[:8])
		if _, exists := newKeys[key]; exists {
			log.Info("WARNING: 8-byte BPF key collision detected — two secrets share the same prefix, one will be shadowed", "hash", hash, "prefix", shadowPrefix[:8])
		}
		newKeys[key] = struct{}{}

		var val secretValue
		val.Len = uint32(len(entry.Value))
		if val.Len > 128 {
			log.V(1).Info("Truncating secret value to max BPF size (128)", "hash", hash)
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
			if len(host) > 32 {
				host = host[:32]
			}
			val.HostLen = uint32(len(host))
			copy(val.AllowedHost[:], host)
		}
		// HostLen == 0 means wildcard (allow all hosts)

		if err := secretMap.Update(&key, &val, 0); err != nil {
			log.Error(err, "failed to update BPF secret_map", "hash", hash)
		} else {
			log.Info("Synced secret into eBPF map", "hash", hash, "hostLen", val.HostLen)
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
		log.Error(err, "error iterating BPF secret_map for pruning")
	}
	for i := range staleKeys {
		if err := secretMap.Delete(&staleKeys[i]); err != nil {
			log.Error(err, "failed to delete stale BPF secret_map entry")
		} else {
			log.Info("Pruned stale entry from eBPF map")
		}
	}

	return nil
}
