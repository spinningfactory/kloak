package ebpf

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spinningfactory/kloak/pkg/logging"
)

func syncSecrets(ctx context.Context, secretMap, watchedHostsMap *ebpf.Map, reader client.Reader, log *zap.SugaredLogger) error {
	if reader == nil {
		return nil
	}

	// List all enabled secrets and all shadow secrets in one pass each
	var enabledSecrets corev1.SecretList
	if err := reader.List(ctx, &enabledSecrets, client.MatchingLabels{"getkloak.io/enabled": "true"}); err != nil {
		return fmt.Errorf("failed to list enabled secrets: %w", err)
	}

	var shadowSecrets corev1.SecretList
	if err := reader.List(ctx, &shadowSecrets, client.MatchingLabels{"getkloak.io/managed": "true"}); err != nil {
		return fmt.Errorf("failed to list shadow secrets: %w", err)
	}

	// Build shadow lookup map: "namespace/name-kloak" -> *Secret
	shadowMap := make(map[string]*corev1.Secret, len(shadowSecrets.Items))
	for i := range shadowSecrets.Items {
		s := &shadowSecrets.Items[i]
		shadowMap[s.Namespace+"/"+s.Name] = s
	}

	// newKeys tracks which keys we upsert so we can prune stale entries afterwards.
	newKeys := make(map[secretKey]struct{})
	// newHosts tracks unique hostnames to sync to watched_hosts map.
	newHosts := make(map[watchedHostKey]struct{})

	for i := range enabledSecrets.Items {
		secret := &enabledSecrets.Items[i]

		// Look up the corresponding shadow secret from the pre-built map
		shadowName := secret.Name + "-kloak"
		shadowSecret, ok := shadowMap[secret.Namespace+"/"+shadowName]
		if !ok {
			logging.Tracew(log, "shadow secret not found, skipping", "secret", secret.Name, "namespace", secret.Namespace)
			continue
		}

		// Parse allowed hosts from the secret's labels
		var allowedHost string
		if hostsLabel, ok := secret.Labels["getkloak.io/hosts"]; ok && hostsLabel != "" {
			parts := strings.Split(hostsLabel, ",")
			for _, p := range parts {
				if trimmed := strings.TrimSpace(p); trimmed != "" && trimmed != "*" {
					allowedHost = trimmed
					break // eBPF map supports one host per entry
				}
			}
		}

		// Parse port spec from the secret's labels
		var port uint16
		var protocol uint8
		if portLabel, ok := secret.Labels["getkloak.io/port"]; ok && portLabel != "" {
			ps, err := parseSyncPortSpec(portLabel)
			if err != nil {
				log.Errorw("Invalid port specification, treating as wildcard", "error", err, "secret", secret.Name)
			} else {
				port = ps.port
				protocol = ps.protocol
			}
		}

		for key, realBytes := range secret.Data {
			shadowBytes, ok := shadowSecret.Data[key]
			if !ok {
				continue
			}

			shadowPrefix := string(shadowBytes)
			realValue := string(realBytes)

			// The BPF program looks up the first 8 bytes.
			// Minimum secret size is 8 bytes (kloak: + 2 UUID chars).
			if len(shadowPrefix) < 8 {
				logging.Tracew(log, "skipping secret too short for BPF key", "secret", secret.Name, "key", key, "len", len(shadowPrefix))
				continue
			}

			var bpfKey secretKey
			copy(bpfKey.Prefix[:], []byte(shadowPrefix)[:8])
			if _, exists := newKeys[bpfKey]; exists {
				log.Errorw("8-byte BPF key collision detected — two secrets share the same prefix, one will be shadowed",
					"secret", secret.Name, "key", key, "prefix", shadowPrefix[:8])
			}
			newKeys[bpfKey] = struct{}{}

			var val secretValue
			val.Len = uint32(len(realValue))
			if val.Len > 128 {
				logging.Tracew(log, "truncating secret value to max BPF size (128)", "secret", secret.Name, "key", key)
				val.Len = 128
			}
			copy(val.RealSecret[:], []byte(realValue)[:val.Len])

			// Store the full prefix (up to 42 bytes) for post-lookup verification.
			prefixLen := len(shadowPrefix)
			if prefixLen > 42 {
				prefixLen = 42
			}
			val.PrefixLen = uint32(prefixLen)
			copy(val.FullPrefix[:], []byte(shadowPrefix)[:prefixLen])

			// Set allowed host for host-based filtering
			if allowedHost != "" {
				host := allowedHost
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
			val.Port = port
			val.Protocol = protocol

			if err := secretMap.Update(&bpfKey, &val, 0); err != nil {
				log.Errorw("failed to update BPF secret_map", "error", err, "secret", secret.Name, "key", key)
			} else {
				logging.Tracew(log, "synced secret into eBPF map", "secret", secret.Name, "key", key, "hostLen", val.HostLen, "port", val.Port, "protocol", val.Protocol)
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
			huffReal := hpack.AppendHuffmanString(nil, realValue)
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
						log.Errorw("failed to update BPF secret_map (Huffman)", "error", err, "secret", secret.Name, "key", key)
					} else {
						logging.Tracew(log, "synced Huffman secret into eBPF map", "secret", secret.Name, "key", key, "huffLen", huffLen)
					}
				}
			} else if len(huffShadow) >= 8 && realHuffLen > len(huffShadow) {
				// This should not happen if the secret reconciler generates shadows
				// with sufficient Huffman length, but log it just in case.
				logging.Tracew(log, "skipping HTTP/2 Huffman variant — shadow Huffman too short",
					"secret", secret.Name, "key", key, "shadowHuffLen", len(huffShadow), "realHuffLen", realHuffLen)
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

	log.Debugw("secret sync complete", "enabledSecrets", len(enabledSecrets.Items), "bpfKeys", len(newKeys), "pruned", len(staleKeys), "watchedHosts", len(newHosts))

	return nil
}

// syncPortSpec holds parsed port and protocol for sync.go (duplicated from
// controller package to avoid a cross-package dependency).
type syncPortSpec struct {
	port     uint16
	protocol uint8
}

func parseSyncPortSpec(spec string) (syncPortSpec, error) {
	spec = strings.TrimSpace(spec)
	spec = strings.ToLower(spec)

	protoStr := "tcp"
	parts := strings.Split(spec, "/")
	if len(parts) == 0 || len(parts) > 2 {
		return syncPortSpec{}, fmt.Errorf("invalid port format: %s", spec)
	} else if len(parts) == 2 {
		protoStr = parts[1]
	}
	portStr := parts[0]

	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return syncPortSpec{}, err
	} else if p == 0 || p > 65535 {
		return syncPortSpec{}, fmt.Errorf("invalid port: %d", p)
	}

	var proto uint8
	switch protoStr {
	case "tcp":
		proto = uint8(unix.IPPROTO_TCP)
	case "udp":
		proto = uint8(unix.IPPROTO_UDP)
	default:
		return syncPortSpec{}, fmt.Errorf("invalid proto: %s", protoStr)
	}

	return syncPortSpec{port: uint16(p), protocol: proto}, nil
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
			logging.Tracew(log, "pruned stale watched host")
		}
	}
}

// syncPodSecrets syncs BPF maps for just the kloak-enabled secrets mounted by
// a specific pod. Reads each secret directly via the API client (bypasses the
// informer cache). Does not prune — only adds/updates entries.
func syncPodSecrets(ctx context.Context, secretMap, watchedHostsMap *ebpf.Map, reader client.Reader, pod *corev1.Pod, log *zap.SugaredLogger) error {
	if reader == nil || pod == nil {
		return nil
	}

	// Collect secret names from the pod's volumes. The webhook rewrites
	// volumes to use shadow secrets (-kloak suffix). We need both the
	// original (for labels/hosts) and the shadow (for kloak: values).
	for _, vol := range pod.Spec.Volumes {
		if vol.Secret == nil {
			continue
		}
		secretName := vol.Secret.SecretName

		// Determine original and shadow names. The webhook rewrites
		// "my-secret" → "my-secret-kloak". If the mounted name ends
		// with -kloak, the original is the name without the suffix.
		var originalName, shadowName string
		if strings.HasSuffix(secretName, "-kloak") {
			shadowName = secretName
			originalName = strings.TrimSuffix(secretName, "-kloak")
		} else {
			// Not a kloak-managed volume — skip.
			continue
		}

		// Read the original secret (has labels with host restrictions)
		var original corev1.Secret
		if err := reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: originalName}, &original); err != nil {
			logging.Tracew(log, "original secret not found for pod sync", "secret", originalName, "pod", pod.Name)
			continue
		}

		// Must be kloak-enabled
		if original.Labels["getkloak.io/enabled"] != "true" {
			continue
		}

		// Read the shadow secret (has kloak: UUID values)
		var shadow corev1.Secret
		if err := reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: shadowName}, &shadow); err != nil {
			logging.Tracew(log, "shadow secret not found for pod sync", "secret", shadowName, "pod", pod.Name)
			continue
		}

		// Parse host restriction from original secret's labels
		var allowedHost string
		if hostsLabel, ok := original.Labels["getkloak.io/hosts"]; ok && hostsLabel != "" {
			parts := strings.Split(hostsLabel, ",")
			for _, p := range parts {
				if trimmed := strings.TrimSpace(p); trimmed != "" && trimmed != "*" {
					allowedHost = trimmed
					break
				}
			}
		}

		// Parse port restriction
		var port uint16
		var protocol uint8
		if portLabel, ok := original.Labels["getkloak.io/port"]; ok && portLabel != "" {
			ps, err := parseSyncPortSpec(portLabel)
			if err == nil {
				port = ps.port
				protocol = ps.protocol
			}
		}

		// Sync each key in the secret to the BPF map
		for key, realBytes := range original.Data {
			shadowBytes, ok := shadow.Data[key]
			if !ok {
				continue
			}

			shadowPrefix := string(shadowBytes)
			realValue := string(realBytes)

			if len(shadowPrefix) < 8 {
				continue
			}

			var bpfKey secretKey
			copy(bpfKey.Prefix[:], []byte(shadowPrefix)[:8])

			var val secretValue
			val.Len = uint32(len(realValue))
			if val.Len > 128 {
				val.Len = 128
			}
			copy(val.RealSecret[:], []byte(realValue)[:val.Len])

			prefixLen := len(shadowPrefix)
			if prefixLen > 42 {
				prefixLen = 42
			}
			val.PrefixLen = uint32(prefixLen)
			copy(val.FullPrefix[:], []byte(shadowPrefix)[:prefixLen])

			if allowedHost != "" {
				host := allowedHost
				if len(host) > len(val.AllowedHost) {
					host = host[:len(val.AllowedHost)]
				}
				val.HostLen = uint32(len(host))
				copy(val.AllowedHost[:], host)

				// Add to watched_hosts so DNS responses for this host are captured
				if watchedHostsMap != nil {
					var whk watchedHostKey
					copy(whk.Host[:], host)
					whVal := uint8(1)
					_ = watchedHostsMap.Update(&whk, &whVal, 0)
				}
			}

			val.Port = port
			val.Protocol = protocol

			if err := secretMap.Update(&bpfKey, &val, 0); err != nil {
				log.Errorw("failed to sync pod secret to BPF map", "error", err, "secret", originalName, "key", key)
			} else {
				logging.Tracew(log, "synced pod secret to BPF map", "secret", originalName, "key", key, "hostLen", val.HostLen, "pod", pod.Name)
			}

			// Also sync Huffman variant
			huffShadow := hpack.AppendHuffmanString(nil, shadowPrefix)
			huffReal := hpack.AppendHuffmanString(nil, realValue)
			if len(huffShadow) >= 8 && len(huffReal) > 0 {
				for len(huffReal) < len(huffShadow) {
					huffReal = append(huffReal, 0xff)
				}
				var huffKey secretKey
				copy(huffKey.Prefix[:], huffShadow[:8])

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

				_ = secretMap.Update(&huffKey, &huffVal, 0)
			}
		}

		log.Infow("synced pod secret for uprobe attachment", "original", originalName, "shadow", shadowName, "host", allowedHost, "pod", pod.Name)
	}

	return nil
}
