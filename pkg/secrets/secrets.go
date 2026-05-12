// Package secrets defines the boundary between kloak's control plane (which
// decides which secrets exist and what they should be rewritten to) and its
// eBPF data plane (which carries out the rewrite in-kernel). The data plane
// consumes any implementation of Source; the kubernetes-driven implementation
// lives in pkg/secrets/k8s.
package secrets

import (
	"context"
	"net"
)

// Secret describes one secret pair the data plane should program into its
// BPF map: a real value that the kernel rewrites to, the shadow placeholder
// the application sees in user space, and the filter constraints under which
// the rewrite is allowed.
//
// The struct is intentionally a *semantic* representation, not the BPF wire
// layout. The data plane in pkg/ebpf/sync.go translates a []Secret into the
// fixed-size struct secretValue at sync time.
type Secret struct {
	// OwnerID identifies the logical producer of this secret. Used for
	// 8-byte-prefix collision tracking when generating shadows; two
	// entries with the same OwnerID are treated as siblings (a shadow
	// being regenerated for the same owner is not a collision with its
	// own previous value).
	OwnerID string

	// Key is a sub-identifier within an owner: a Kubernetes Secret can
	// have multiple data keys; YAML entries today have one key per
	// entry. The (OwnerID, Key) pair is unique within a snapshot.
	Key string

	// Real is the real secret value. The kernel rewrites Shadow → Real
	// in TLS writes that match the Host/IP/Port filters below.
	Real string

	// Shadow is the placeholder the application sees and the BPF map
	// keys off (the first 8 bytes are the lookup key).
	Shadow string

	// Host is a hostname filter. If non-empty, the rewrite happens only
	// on connections whose connect-time destination IP came from a DNS
	// answer for this hostname (the BPF dns_ip_map / conn_ip_map chain
	// enforces this). Empty means any host.
	Host string

	// IP is an alternative to Host: a literal destination IP that
	// bypasses DNS verification. Mutually exclusive with Host (k8s
	// adapter populates this when Host parses as a literal IP).
	IP net.IP

	// Port is a TCP/UDP port filter. 0 means any port.
	Port uint16

	// Protocol is unix.IPPROTO_TCP / IPPROTO_UDP, or 0 for any.
	Protocol uint8
}

// Source produces snapshots of the secrets the data plane should program
// into its BPF maps. Implementations may be backed by a Kubernetes
// informer cache, a YAML file, or any other origin.
//
// Snapshot is called repeatedly by pkg/ebpf/sync.go; implementations
// should be cheap and re-entrant. Returned slices must not be mutated
// by the caller.
type Source interface {
	Snapshot(ctx context.Context) ([]Secret, error)
}
