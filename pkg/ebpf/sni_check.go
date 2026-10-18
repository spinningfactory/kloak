package ebpf

import (
	"bytes"
	"fmt"
	"strings"
)

// maxHostLen is MAX_HOST_LEN in tls_uprobe.c: the size of the host buffers
// in secret_value, sni_state and secret_binding_event.
const maxHostLen = 64

// SNICheckMode selects what the data plane does when a secret restricted to
// a hostname (getkloak.io/hosts) is written on a connection whose TLS
// ClientHello did not name that host (see sni_state in tls_uprobe.c).
type SNICheckMode string

const (
	// SNICheckEnforce refuses the rewrite: the placeholder goes out
	// unchanged. This is the default and the BPF map's zero value.
	SNICheckEnforce SNICheckMode = "enforce"
	// SNICheckAudit lets the rewrite go ahead but still reports it. Meant
	// for finding clients whose SNI differs from the annotated host (for
	// example a short in-cluster service name) before enforcing.
	SNICheckAudit SNICheckMode = "audit"
)

// Values of the sni_check_mode BPF map (SNI_CHECK_* in tls_uprobe.c).
const (
	sniCheckModeEnforce uint32 = 0
	sniCheckModeAudit   uint32 = 1
)

// ParseSNICheckMode validates a --sni-check value.
func ParseSNICheckMode(s string) (SNICheckMode, error) {
	switch SNICheckMode(strings.ToLower(strings.TrimSpace(s))) {
	case "", SNICheckEnforce:
		return SNICheckEnforce, nil
	case SNICheckAudit:
		return SNICheckAudit, nil
	default:
		return "", fmt.Errorf("invalid SNI check mode %q (want enforce or audit)", s)
	}
}

func (m SNICheckMode) bpfValue() uint32 {
	if m == SNICheckAudit {
		return sniCheckModeAudit
	}
	return sniCheckModeEnforce
}

// sniStatusNames names the SNI_STATUS_* values of helpers.h, as reported in
// secret_binding_event.sni_status.
var sniStatusNames = map[uint8]string{
	0: "no ClientHello seen on the connection",
	2: "ClientHello without SNI",
	3: "encrypted ClientHello (ECH)",
	4: "ClientHello too large to read the SNI",
	5: "malformed ClientHello",
	6: "SNI does not match the secret's host",
}

// describeSNIEvent returns why an SNI check refused (or, in audit mode,
// flagged) a rewrite, and the SNI the connection carried, if any.
func describeSNIEvent(ev secretBindingEvent) (reason, sni string) {
	reason, ok := sniStatusNames[ev.SNIStatus]
	if !ok {
		reason = fmt.Sprintf("SNI status %d", ev.SNIStatus)
	}
	if n := bytes.IndexByte(ev.SNI[:], 0); n >= 0 {
		sni = string(ev.SNI[:n])
	} else {
		sni = string(ev.SNI[:])
	}
	return reason, sni
}
