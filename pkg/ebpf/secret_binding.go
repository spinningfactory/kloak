package ebpf

import (
	"fmt"
	"net/netip"
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

// Values of secret_binding_event.reason (SECRET_EVT_* in tls_uprobe.c).
const (
	secretEventBinding uint8 = 0 // the pod does not reference the secret
	secretEventSNI     uint8 = 1 // the connection's SNI is not the secret's host
)

// secretBindingEvent must match struct secret_binding_event in tls_uprobe.c.
type secretBindingEvent struct {
	CgroupID  uint64
	Tgid      uint32
	Audit     uint8
	Reason    uint8
	SNIStatus uint8
	MemoryBIO uint8
	Key       placeholderKey
	SNI       [maxHostLen]byte
}

// podBinding is what a pod is entitled to redeem: every container cgroup
// of the pod may redeem the secrets the pod references.
type podBinding struct {
	pod       string // namespace/name, for logs
	podIPs    []netip.Addr
	cgroupIDs []uint64
	refs      []secrets.Ref
}

// secretsByRef indexes a snapshot by owner and data key, to resolve
// secrets.Ref.
type secretsByRef map[string]map[string]*secrets.Secret

func indexSecrets(snapshot []secrets.Secret) secretsByRef {
	ix := make(secretsByRef)
	for i := range snapshot {
		s := &snapshot[i]
		if ix[s.OwnerID] == nil {
			ix[s.OwnerID] = make(map[string]*secrets.Secret)
		}
		ix[s.OwnerID][s.Key] = s
	}
	return ix
}

// each calls fn for every secret ref grants: all of its owner's keys, or
// the ones ref.Keys names. A Ref whose owner or key is not in the snapshot
// grants nothing.
func (ix secretsByRef) each(ref secrets.Ref, fn func(*secrets.Secret)) {
	owned := ix[ref.OwnerID]
	if ref.Keys == nil {
		for _, s := range owned {
			fn(s)
		}
		return
	}
	for _, k := range ref.Keys {
		if s, ok := owned[k]; ok {
			fn(s)
		}
	}
}

// secretACL returns the secret_acl entries the bindings grant over the
// snapshot.
func secretACL(snapshot []secrets.Secret, bindings map[string]podBinding) map[secretACLKey]struct{} {
	ix := indexSecrets(snapshot)
	acl := make(map[secretACLKey]struct{})
	for _, b := range bindings {
		for _, ref := range b.refs {
			ix.each(ref, func(s *secrets.Secret) {
				for _, k := range placeholderKeys(s.Shadow) {
					for _, cg := range b.cgroupIDs {
						acl[secretACLKey{CgroupID: cg, Key: k}] = struct{}{}
					}
				}
			})
		}
	}
	return acl
}

// vipPodHostKey must match struct vip_pod_host_key in tls_uprobe.c.
type vipPodHostKey struct {
	PodIP [16]byte         // IPv4-mapped-IPv6 or IPv6
	Host  [maxHostLen]byte // all zero: every watched host
}

// vipPodHosts returns the vip_pod_host entries for the bindings over the
// snapshot: each address of a pod, paired with the host of every
// secret the pod references that is restricted to a hostname, so that
// tc_dns_rewrite hands the pod those hosts' fake IPs. anyHost
// (--secret-binding=audit, where a pod may redeem every secret) pairs each
// address with every watched host instead.
func vipPodHosts(snapshot []secrets.Secret, bindings map[string]podBinding, anyHost bool) map[vipPodHostKey]struct{} {
	ix := indexSecrets(snapshot)
	out := make(map[vipPodHostKey]struct{})
	for _, b := range bindings {
		for _, ip := range b.podIPs {
			addr := vipPodHostKey{PodIP: ip.Unmap().As16()}
			if anyHost {
				out[addr] = struct{}{}
				continue
			}
			for _, ref := range b.refs {
				ix.each(ref, func(s *secrets.Secret) {
					// The hosts applySecrets returns.
					if s.Host == "" || len(s.Host) >= maxHostLen {
						return
					}
					k := addr
					copy(k.Host[:], s.Host)
					out[k] = struct{}{}
				})
			}
		}
	}
	return out
}

// describeBindingEvent names the pod and secret behind a violation event,
// for the controller log. bindings and snapshot are best-effort context:
// a cgroup outside every binding belongs to a pod kloak doesn't track.
func describeBindingEvent(ev *secretBindingEvent, bindings map[string]podBinding, snapshot []secrets.Secret) (pod, secret string) {
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
