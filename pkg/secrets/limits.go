package secrets

import "fmt"

// Secret value lengths. A kloak-enabled value is accepted when it is at
// least ShadowPrefixLen bytes (its placeholder's first ShadowPrefixLen bytes
// are the data plane's lookup key) and at most EffectiveMaxLen(policy)
// bytes, the policy being the cluster's configured maximum (Helm
// secrets.maxLength, --max-secret-length on the controller and the webhook).
// The webhook rejects a Secret with a longer value at admission; the
// controller's sync leaves such a value out of the data plane (its
// placeholder goes out unchanged: never a truncated rewrite).
const (
	// DataPlaneMaxLen is the longest value the eBPF data plane can rewrite
	// today: SECRET_MAX_LEN in pkg/ebpf/bpf/tls_uprobe.c, the size of
	// secret_value.real_secret and of every patch's XOR delta.
	//
	// TODO(kloak#383): raise it as the data plane takes longer secrets:
	// phase 1 (the patch from the chunked secret store, a placeholder
	// within one TLS record and one segment), phase 2 (a record over
	// several segments, retransmits), phase 3 (several records and writes).
	// After phase 3 it no longer limits the policy, and EffectiveMaxLen is
	// the policy itself.
	DataPlaneMaxLen = 128

	// DefaultMaxLen is the policy's default: 64 KiB.
	DefaultMaxLen = 64 << 10

	// MaxLenLimit is the most the policy may be set to: 1 MiB, Kubernetes'
	// limit on a whole Secret.
	MaxLenLimit = 1 << 20
)

// ValidateMaxLen checks a configured policy maximum: in [ShadowPrefixLen,
// MaxLenLimit].
func ValidateMaxLen(policy int) error {
	if policy < ShadowPrefixLen || policy > MaxLenLimit {
		return fmt.Errorf("maximum secret length %d is out of range [%d, %d]", policy, ShadowPrefixLen, MaxLenLimit)
	}
	return nil
}

// EffectiveMaxLen returns the longest value accepted under a policy
// maximum: the policy, clamped to what the data plane can rewrite
// (DataPlaneMaxLen) and to MaxLenLimit. A policy below ShadowPrefixLen is
// taken as ShadowPrefixLen (ValidateMaxLen refuses it in configuration).
func EffectiveMaxLen(policy int) int {
	return max(ShadowPrefixLen, min(policy, DataPlaneMaxLen, MaxLenLimit))
}
