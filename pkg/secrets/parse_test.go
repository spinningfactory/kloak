package secrets

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseHost(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantIP   net.IP
	}{
		{"", "", nil},
		{"*", "", nil},
		{"  ", "", nil},
		{"api.stripe.com", "api.stripe.com", nil},
		{"  api.stripe.com  ", "api.stripe.com", nil},
		{"127.0.0.1", "", net.ParseIP("127.0.0.1")},
		{"::1", "", net.ParseIP("::1")},
	}
	for _, tc := range cases {
		gotHost, gotIP := ParseHost(tc.in)
		if gotHost != tc.wantHost {
			t.Errorf("ParseHost(%q): host=%q want %q", tc.in, gotHost, tc.wantHost)
		}
		if !gotIP.Equal(tc.wantIP) {
			t.Errorf("ParseHost(%q): ip=%v want %v", tc.in, gotIP, tc.wantIP)
		}
	}
}

func TestParsePort(t *testing.T) {
	tcp := uint8(unix.IPPROTO_TCP)
	udp := uint8(unix.IPPROTO_UDP)
	cases := []struct {
		in      string
		want    PortSpec
		wantErr bool
	}{
		{"443", PortSpec{Port: 443, Protocol: tcp}, false},
		{"443/tcp", PortSpec{Port: 443, Protocol: tcp}, false},
		{"53/udp", PortSpec{Port: 53, Protocol: udp}, false},
		{" 443/TCP ", PortSpec{Port: 443, Protocol: tcp}, false},
		// Spaces around the slash should be tolerated.
		{"443 / tcp", PortSpec{Port: 443, Protocol: tcp}, false},
		{" 53 /udp ", PortSpec{Port: 53, Protocol: udp}, false},
		{"", PortSpec{}, true},
		{"0", PortSpec{}, true},
		{"99999", PortSpec{}, true},
		{"443/sctp", PortSpec{}, true},
		{"abc", PortSpec{}, true},
		{"443/tcp/extra", PortSpec{}, true},
	}
	for _, tc := range cases {
		got, err := ParsePort(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParsePort(%q): err=%v wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParsePort(%q): got %+v want %+v", tc.in, got, tc.want)
		}
	}
}
