package ebpf

import (
	"fmt"
	"strings"

	"golang.org/x/net/http2/hpack"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// SecretBindingMode selects what the data plane does when a process redeems
// a placeholder of a secret its pod does not reference (see secret_acl in
// tls_uprobe.c).
type SecretBindingMode string

const (
	// SecretBindingEnforce refuses the rewrite: the placeholder goes out
	// unchanged. This is the default and the BPF map's zero value.
	SecretBindingEnforce SecretBindingMode = "enforce"
	// SecretBindingAudit lets the rewrite go ahead but still reports it.
	// Meant for finding workloads that redeem secrets they don't mount
	// before switching to enforce.
	SecretBindingAudit SecretBindingMode = "audit"
)

// Values of the secret_binding_mode BPF map (SECRET_BINDING_* in tls_uprobe.c).
const (
	secretBindingModeEnforce uint32 = 0
	secretBindingModeAudit   uint32 = 1
)

// ParseSecretBindingMode validates a --secret-binding value.
func ParseSecretBindingMode(s string) (SecretBindingMode, error) {
	switch SecretBindingMode(strings.ToLower(strings.TrimSpace(s))) {
	case "", SecretBindingEnforce:
		return SecretBindingEnforce, nil
	case SecretBindingAudit:
		return SecretBindingAudit, nil
	default:
		return "", fmt.Errorf("invalid secret binding mode %q (want enforce or audit)", s)
	}
}

func (m SecretBindingMode) bpfValue() uint32 {
	if m == SecretBindingAudit {
		return secretBindingModeAudit
	}
	return secretBindingModeEnforce
}

// placeholderKey is the BPF lookup key of a placeholder: its first
// secrets.ShadowPrefixLen bytes, as stored in secret_map.
type placeholderKey [secrets.ShadowPrefixLen]byte

// placeholderKeys returns the BPF keys under which a shadow can appear on
// the wire: the raw placeholder, plus its HPACK-Huffman encoding (HTTP/2).
// Must match how syncSecrets keys secret_map.
func placeholderKeys(shadow string) []placeholderKey {
	if len(shadow) < secrets.ShadowPrefixLen {
		return nil
	}
	var raw placeholderKey
	copy(raw[:], shadow)
	keys := []placeholderKey{raw}
	if huff, ok := huffmanPlaceholderKey(shadow); ok {
		keys = append(keys, huff)
	}
	return keys
}

// huffmanPlaceholderKey returns the BPF key of the shadow's HPACK-Huffman
// encoding, or false when the encoding is too short to carry a key.
func huffmanPlaceholderKey(shadow string) (placeholderKey, bool) {
	var k placeholderKey
	huff := hpack.AppendHuffmanString(nil, shadow)
	if len(huff) < len(k) {
		return k, false
	}
	copy(k[:], huff)
	return k, true
}

// secretACLKey must match struct secret_acl_key in tls_uprobe.c.
type secretACLKey struct {
	CgroupID uint64
	Key      placeholderKey
}

// secretBindingEvent must match struct secret_binding_event in tls_uprobe.c.
type secretBindingEvent struct {
	CgroupID uint64
	Tgid     uint32
	Audit    uint8
	_        [3]byte
	Key      placeholderKey
}

// podBinding is what a pod is entitled to redeem: every container cgroup
// of the pod may redeem the secrets the pod references.
type podBinding struct {
	pod       string // namespace/name, for logs
	cgroupIDs []uint64
	refs      []secrets.Ref
}

// secretACL returns the secret_acl entries the bindings grant over the
// snapshot. A Ref whose owner or key is not in the snapshot grants nothing.
func secretACL(snapshot []secrets.Secret, bindings map[string]podBinding) map[secretACLKey]struct{} {
	// owner → data key → placeholder keys
	byOwner := make(map[string]map[string][]placeholderKey)
	for i := range snapshot {
		s := &snapshot[i]
		keys := placeholderKeys(s.Shadow)
		if len(keys) == 0 {
			continue
		}
		if byOwner[s.OwnerID] == nil {
			byOwner[s.OwnerID] = make(map[string][]placeholderKey)
		}
		byOwner[s.OwnerID][s.Key] = keys
	}

	acl := make(map[secretACLKey]struct{})
	grant := func(cgroupIDs []uint64, keys []placeholderKey) {
		for _, cg := range cgroupIDs {
			for _, k := range keys {
				acl[secretACLKey{CgroupID: cg, Key: k}] = struct{}{}
			}
		}
	}
	for _, b := range bindings {
		for _, ref := range b.refs {
			owned := byOwner[ref.OwnerID]
			if ref.Keys == nil {
				for _, keys := range owned {
					grant(b.cgroupIDs, keys)
				}
				continue
			}
			for _, k := range ref.Keys {
				grant(b.cgroupIDs, owned[k])
			}
		}
	}
	return acl
}

// describeBindingEvent names the pod and secret behind a violation event,
// for the controller log. bindings and snapshot are best-effort context:
// a cgroup outside every binding belongs to a pod kloak doesn't track.
func describeBindingEvent(ev secretBindingEvent, bindings map[string]podBinding, snapshot []secrets.Secret) (pod, secret string) {
	pod = fmt.Sprintf("untracked cgroup %d", ev.CgroupID)
	for _, b := range bindings {
		for _, cg := range b.cgroupIDs {
			if cg == ev.CgroupID {
				pod = b.pod
			}
		}
	}
	secret = "unknown"
	for i := range snapshot {
		for _, k := range placeholderKeys(snapshot[i].Shadow) {
			if k == ev.Key {
				return pod, snapshot[i].OwnerID + "[" + snapshot[i].Key + "]"
			}
		}
	}
	return pod, secret
}
