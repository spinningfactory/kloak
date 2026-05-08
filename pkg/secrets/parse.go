package secrets

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ParseHost interprets a host filter string. Empty input or "*" returns
// ("", nil), meaning no filter. A literal IP returns ("", parsed IP);
// any other non-empty value returns (hostname, nil).
//
// Used by every Source that accepts host filters as a free-form string
// (k8s annotation, future YAML, ...).
func ParseHost(spec string) (host string, ip net.IP) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" || trimmed == "*" {
		return "", nil
	}
	if parsed := net.ParseIP(trimmed); parsed != nil {
		return "", parsed
	}
	return trimmed, nil
}

// PortSpec is the parsed form of a "<port>" or "<port>/<proto>" string.
type PortSpec struct {
	Port     uint16
	Protocol uint8 // unix.IPPROTO_TCP or unix.IPPROTO_UDP
}

// ParsePort parses "443" or "443/tcp" / "53/udp". Defaults to TCP when
// the protocol is omitted. Empty input is invalid; callers that treat
// "no port filter" as wildcard should check the empty case before
// calling.
func ParsePort(spec string) (PortSpec, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" {
		return PortSpec{}, fmt.Errorf("empty port spec")
	}

	protoStr := "tcp"
	parts := strings.Split(spec, "/")
	switch len(parts) {
	case 1:
		// just a port, default proto
	case 2:
		// Trim each part — the user might write "80 / tcp" with spaces
		// around the slash; outer TrimSpace above doesn't reach here.
		protoStr = strings.TrimSpace(parts[1])
	default:
		return PortSpec{}, fmt.Errorf("invalid port format: %s", spec)
	}

	p, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return PortSpec{}, fmt.Errorf("invalid port: %w", err)
	}
	if p == 0 || p > 65535 {
		return PortSpec{}, fmt.Errorf("port out of range: %d", p)
	}

	var proto uint8
	switch protoStr {
	case "tcp":
		proto = uint8(unix.IPPROTO_TCP)
	case "udp":
		proto = uint8(unix.IPPROTO_UDP)
	default:
		return PortSpec{}, fmt.Errorf("invalid protocol: %s", protoStr)
	}

	return PortSpec{Port: uint16(p), Protocol: proto}, nil
}
