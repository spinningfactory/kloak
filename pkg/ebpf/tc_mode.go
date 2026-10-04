package ebpf

import (
	"fmt"
	"strings"
)

// TCAttachMode selects how the tc patch program is attached to an interface.
type TCAttachMode string

const (
	// TCAttachAuto uses TCX when the kernel supports it (Linux 6.6+) and
	// falls back to a classic clsact/cls_bpf filter otherwise.
	TCAttachAuto TCAttachMode = "auto"
	// TCAttachTCX always uses TCX links. Fails on kernels older than 6.6.
	TCAttachTCX TCAttachMode = "tcx"
	// TCAttachClsact always uses a classic clsact qdisc + cls_bpf filter.
	// Works on every kernel Kloak supports (5.17+). Mainly useful to
	// exercise the fallback path on a TCX-capable kernel.
	TCAttachClsact TCAttachMode = "clsact"
)

// ParseTCAttachMode validates a --tc-attach-mode value.
func ParseTCAttachMode(s string) (TCAttachMode, error) {
	switch TCAttachMode(strings.ToLower(strings.TrimSpace(s))) {
	case "", TCAttachAuto:
		return TCAttachAuto, nil
	case TCAttachTCX:
		return TCAttachTCX, nil
	case TCAttachClsact:
		return TCAttachClsact, nil
	default:
		return "", fmt.Errorf("invalid tc attach mode %q (want auto, tcx or clsact)", s)
	}
}
