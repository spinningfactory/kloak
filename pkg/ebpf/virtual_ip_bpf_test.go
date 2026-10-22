//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"github.com/spinningfactory/kloak/pkg/cgroups"
)

var (
	vipTestFake   = netip.MustParseAddr("198.18.0.5")
	vipTestFake2  = netip.MustParseAddr("198.18.0.6")
	vipTestFake6  = netip.MustParseAddr("2001:2::5")
	vipTestFake62 = netip.MustParseAddr("2001:2::6")
	vipTestDNS    = netip.MustParseAddr("10.43.0.10")
	vipTestDNS6   = netip.MustParseAddr("fd43::a")
	vipTestPod    = netip.MustParseAddr("10.42.0.7")
	vipTestPod6   = netip.MustParseAddr("fd42::7")
	vipTestReal   = []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")}
	vipTestReal6  = []netip.Addr{netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8::11")}
	vipTestHosts  = map[string]netip.Addr{"api.example.com": vipTestFake, "apis.example.com": vipTestFake2}
	vipTestHosts6 = map[string]netip.Addr{"api.example.com": vipTestFake6, "apis.example.com": vipTestFake62}
	vipTestNoHost = "other.example.com"
)

// loadVirtualIPObjects loads the BPF objects with the virtual IP ranges of
// the tests configured, vipTestHosts watched with their fake IPv4s and
// IPv6s, and the pod's addresses (vipTestPod, vipTestPod6) granted them.
func loadVirtualIPObjects(t *testing.T) *tlsuprobeObjects {
	t.Helper()
	objs := loadTestObjects(t)
	setVIPConfig(t, objs, testVIPRanges)
	for host, ip := range vipTestHosts {
		key := vipHostKey(host)
		val := vipHostVal{IP4: ip.As4(), IP6: vipTestHosts6[host].As16()}
		if err := objs.VipHostIp.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		putPodHost(t, objs, vipTestPod, host)
		putPodHost(t, objs, vipTestPod6, host)
	}
	return objs
}

func setVIPConfig(t *testing.T, objs *tlsuprobeObjects, r VirtualIPRanges) {
	t.Helper()
	cfg := vipConfig(r)
	if err := objs.VipConfig.Update(uint32(0), &cfg, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

// putPodHost lets the pod at addr get the fake IP of host (vip_pod_host);
// "" stands for every host.
func putPodHost(t *testing.T, objs *tlsuprobeObjects, addr netip.Addr, host string) {
	t.Helper()
	k := vipPodHostKey{PodIP: addr.As16()}
	copy(k.Host[:], host)
	v := uint8(1)
	if err := objs.VipPodHost.Update(&k, &v, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

// dnsResponse builds a compressed NOERROR response to a query for qname.
func dnsResponse(t *testing.T, qname string, qtype dnsmessage.Type, rcode dnsmessage.RCode, answers func(*dnsmessage.Builder)) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, Response: true, RecursionDesired: true, RecursionAvailable: true, RCode: rcode})
	b.EnableCompression()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(b.StartQuestions())
	must(b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(qname + "."), Type: qtype, Class: dnsmessage.ClassINET}))
	must(b.StartAnswers())
	if answers != nil {
		answers(&b)
	}
	msg, err := b.Finish()
	must(err)
	return msg
}

// aRecords adds an A record (IPv4 ips) or an AAAA record (IPv6 ips) for
// name per address.
func aRecords(t *testing.T, name string, ips ...netip.Addr) func(*dnsmessage.Builder) {
	return func(b *dnsmessage.Builder) {
		for _, ip := range ips {
			h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name + "."), Class: dnsmessage.ClassINET, TTL: 30}
			var err error
			if ip.Is4() {
				err = b.AResource(h, dnsmessage.AResource{A: ip.As4()})
			} else {
				err = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: ip.As16()})
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

// ipFrame wraps an L4 segment in Ethernet and an IPv4 header, or an IPv6
// one when src is IPv6.
func ipFrame(src, dst netip.Addr, proto uint8, l4 []byte) []byte {
	if src.Is6() {
		f := make([]byte, 14+40+len(l4))
		binary.BigEndian.PutUint16(f[12:], 0x86DD)
		ip := f[14:54]
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
		ip[6] = proto
		ip[7] = 64
		copy(ip[8:24], src.AsSlice())
		copy(ip[24:40], dst.AsSlice())
		copy(f[54:], l4)
		return f
	}
	f := make([]byte, 14+20+len(l4))
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	ip := f[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], src.AsSlice())
	copy(ip[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(ip[10:], ^onesSum(0, ip))
	copy(f[34:], l4)
	return f
}

// l4Offset returns where the L4 header of a frame built by ipFrame starts.
func l4Offset(f []byte) int {
	if binary.BigEndian.Uint16(f[12:]) == 0x86DD {
		return 14 + 40
	}
	return 14 + 20
}

// udpFrame wraps payload in Ethernet, IPv4 or IPv6 (by src's family) and UDP
// headers. A zero checksum is sent when withCsum is false.
func udpFrame(src, dst netip.Addr, sport, dport uint16, payload []byte, withCsum bool) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	f := ipFrame(src, dst, unix.IPPROTO_UDP, udp)
	if withCsum {
		udp = f[l4Offset(f):]
		c := ^onesSum(udpPseudoSum(f, len(udp)), udp)
		if c == 0 {
			c = 0xFFFF
		}
		binary.BigEndian.PutUint16(udp[6:], c)
	}
	return f
}

func onesSum(sum uint32, b []byte) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return uint16(sum)
}

// udpPseudoSum sums the UDP pseudo-header of frame f (IPv4 or IPv6): the
// addresses, the protocol and the UDP length.
func udpPseudoSum(f []byte, udpLen int) uint32 {
	addrs := f[14+12 : 14+20]
	if l4Offset(f) == 14+40 {
		addrs = f[14+8 : 14+40]
	}
	var s uint32
	for i := 0; i < len(addrs); i += 2 {
		s += uint32(binary.BigEndian.Uint16(addrs[i:]))
	}
	return s + unix.IPPROTO_UDP + uint32(udpLen)
}

// udpChecksumOK verifies the UDP checksum of a frame built by udpFrame.
func udpChecksumOK(f []byte) bool {
	udp := f[l4Offset(f):]
	if binary.BigEndian.Uint16(udp[6:]) == 0 {
		return l4Offset(f) == 14+20 // optional in IPv4 only
	}
	return onesSum(udpPseudoSum(f, len(udp)), udp) == 0xFFFF
}

// answerAddrs returns the A and AAAA record addresses of the DNS message in
// a frame.
func answerAddrs(t *testing.T, f []byte) []netip.Addr {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(f[l4Offset(f)+8:]); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	var out []netip.Addr
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		switch h.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, netip.AddrFrom4(a.A))
		case dnsmessage.TypeAAAA:
			a, err := p.AAAAResource()
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, netip.AddrFrom16(a.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func runTC(t *testing.T, prog *ciliumebpf.Program, in []byte) []byte {
	t.Helper()
	out := make([]byte, len(in))
	ret, err := prog.Run(&ciliumebpf.RunOptions{Data: in, DataOut: out})
	if err != nil {
		t.Fatalf("running %s: %v", prog, err)
	}
	if ret != 0 {
		t.Fatalf("%s returned %d, want TC_ACT_OK", prog, ret)
	}
	return out
}

func readUpstream(t *testing.T, objs *tlsuprobeObjects, fake netip.Addr) (vipUpstreamVal, bool) {
	t.Helper()
	key := dnsIPKey{IP: fake.As16()}
	var v vipUpstreamVal
	err := objs.VipUpstream.Lookup(&key, &v)
	if errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		return v, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return v, true
}

func clearUpstreams(t *testing.T, objs *tlsuprobeObjects) {
	t.Helper()
	for host, ip := range vipTestHosts {
		for _, ip := range []netip.Addr{ip, vipTestHosts6[host]} {
			key := dnsIPKey{IP: ip.As16()}
			if err := objs.VipUpstream.Delete(&key); err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
				t.Fatal(err)
			}
		}
	}
}

// upstreamAddrs returns the addresses of the slots of v that hold one.
func upstreamAddrs(v vipUpstreamVal) []netip.Addr {
	var out []netip.Addr
	for _, s := range v.Slot {
		if s.ExpiresAt != 0 {
			out = append(out, netip.AddrFrom16(s.IP).Unmap())
		}
	}
	return out
}

func bootNanos(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

func TestDNSRewrite(t *testing.T) {
	objs := loadVirtualIPObjects(t)
	prog := objs.TcDnsRewrite

	// The A records of a watched host's answer become its fake IP and the
	// AAAA records its fake IPv6, behind a CNAME chain too, over IPv4 and
	// IPv6, and the real addresses are recorded for the connect redirect.
	// The two hosts' names differ in length by one byte, so their records
	// start at an odd and an even offset (checksum update).
	for _, c := range []struct {
		name     string
		dns, pod netip.Addr
		qtype    dnsmessage.Type
	}{
		{"A", vipTestDNS, vipTestPod, dnsmessage.TypeA},
		{"AAAA", vipTestDNS, vipTestPod, dnsmessage.TypeAAAA},
		{"A over IPv6", vipTestDNS6, vipTestPod6, dnsmessage.TypeA},
		{"AAAA over IPv6", vipTestDNS6, vipTestPod6, dnsmessage.TypeAAAA},
	} {
		real, fakes := vipTestReal, vipTestHosts
		if c.qtype == dnsmessage.TypeAAAA {
			real, fakes = vipTestReal6, vipTestHosts6
		}
		for _, host := range []string{"api.example.com", "apis.example.com"} {
			t.Run(c.name+"/"+host, func(t *testing.T) {
				clearUpstreams(t, objs)
				before := bootNanos(t)
				msg := dnsResponse(t, host, c.qtype, dnsmessage.RCodeSuccess, func(b *dnsmessage.Builder) {
					h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(host + "."), Class: dnsmessage.ClassINET, TTL: 300}
					if err := b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.example.net.")}); err != nil {
						t.Fatal(err)
					}
					aRecords(t, "edge.example.net", real...)(b)
				})
				out := runTC(t, prog, udpFrame(c.dns, c.pod, 53, 40000, msg, true))
				fake := fakes[host]
				if got := answerAddrs(t, out); len(got) != 2 || got[0] != fake || got[1] != fake {
					t.Errorf("records after rewrite: %v, want 2 x %s", got, fake)
				}
				if !udpChecksumOK(out) {
					t.Error("UDP checksum wrong after rewrite")
				}
				up, ok := readUpstream(t, objs, fake)
				if !ok {
					t.Fatal("no vip_upstream entry")
				}
				if got := upstreamAddrs(up); !slices.Equal(got, real) {
					t.Errorf("upstreams %v, want %v", got, real)
				}
				for i := range real {
					// TTL 30 s from now.
					s := up.Slot[i]
					if s.ExpiresAt < before+29*uint64(time.Second) || s.ExpiresAt > bootNanos(t)+30*uint64(time.Second) {
						t.Errorf("slot %d expires at %d, now %d", i, s.ExpiresAt, before)
					}
				}
				// The other family's fake IP gets no upstream from it.
				other := vipTestHosts6[host]
				if c.qtype == dnsmessage.TypeAAAA {
					other = vipTestHosts[host]
				}
				if _, ok := readUpstream(t, objs, other); ok {
					t.Errorf("upstream recorded under %s", other)
				}
			})
		}
	}

	t.Run("zero UDP checksum", func(t *testing.T) {
		msg := dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal[0]))
		out := runTC(t, prog, udpFrame(vipTestDNS, vipTestPod, 53, 40000, msg, false))
		if got := answerAddrs(t, out); len(got) != 1 || got[0] != vipTestFake {
			t.Errorf("A records after rewrite: %v", got)
		}
		if c := binary.BigEndian.Uint16(out[34+6:]); c != 0 {
			t.Errorf("checksum became %#x, want it left at 0", c)
		}
	})

	t.Run("rewritten twice", func(t *testing.T) {
		// Already holding the fake IP, the answer is left alone and the
		// fake IP is not recorded as an upstream.
		for qtype, fake := range map[dnsmessage.Type]netip.Addr{dnsmessage.TypeA: vipTestFake, dnsmessage.TypeAAAA: vipTestFake6} {
			clearUpstreams(t, objs)
			msg := dnsResponse(t, "api.example.com", qtype, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", fake))
			in := udpFrame(vipTestDNS, vipTestPod, 53, 40000, msg, true)
			if out := runTC(t, prog, in); !bytes.Equal(out, in) {
				t.Errorf("%s answer changed", qtype)
			}
			if _, ok := readUpstream(t, objs, fake); ok {
				t.Errorf("fake IP %s recorded as its own upstream", fake)
			}
		}
	})

	t.Run("no IPv6 range", func(t *testing.T) {
		// AAAA answers are left unchanged; A answers are still rewritten.
		setVIPConfig(t, objs, VirtualIPRanges{V4: testVIPRange})
		t.Cleanup(func() { setVIPConfig(t, objs, testVIPRanges) })
		clearUpstreams(t, objs)
		msg := dnsResponse(t, "api.example.com", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal6[0]))
		in := udpFrame(vipTestDNS, vipTestPod, 53, 40000, msg, true)
		if out := runTC(t, prog, in); !bytes.Equal(out, in) {
			t.Error("AAAA answer changed")
		}
		if _, ok := readUpstream(t, objs, vipTestFake6); ok {
			t.Error("vip_upstream written")
		}
		msg = dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal[0]))
		if got := answerAddrs(t, runTC(t, prog, udpFrame(vipTestDNS, vipTestPod, 53, 40000, msg, true))); len(got) != 1 || got[0] != vipTestFake {
			t.Errorf("A records after rewrite: %v", got)
		}
	})

	t.Run("pod scope", func(t *testing.T) {
		scoped := netip.MustParseAddr("10.42.0.8")
		audit := netip.MustParseAddr("10.42.0.9")
		putPodHost(t, objs, scoped, "apis.example.com")
		putPodHost(t, objs, audit, "")
		for _, c := range []struct {
			name      string
			pod       netip.Addr
			host      string
			rewritten bool
		}{
			{"granted the host", scoped, "apis.example.com", true},
			{"granted another host", scoped, "api.example.com", false},
			{"granted every host", audit, "api.example.com", true},
			{"granted nothing", netip.MustParseAddr("10.42.0.10"), "api.example.com", false},
			{"IPv6 address granted nothing", netip.MustParseAddr("fd42::8"), "api.example.com", false},
		} {
			t.Run(c.name, func(t *testing.T) {
				clearUpstreams(t, objs)
				msg := dnsResponse(t, c.host, dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, c.host, vipTestReal[0]))
				dns := vipTestDNS
				if c.pod.Is6() {
					dns = vipTestDNS6
				}
				in := udpFrame(dns, c.pod, 53, 40000, msg, true)
				out := runTC(t, prog, in)
				fake := vipTestHosts[c.host]
				if !c.rewritten {
					if !bytes.Equal(out, in) {
						t.Error("answer changed")
					}
					if _, ok := readUpstream(t, objs, fake); ok {
						t.Error("vip_upstream written")
					}
					return
				}
				if got := answerAddrs(t, out); len(got) != 1 || got[0] != fake {
					t.Errorf("A records after rewrite: %v, want %s", got, fake)
				}
			})
		}
	})

	// Left unchanged: the app gets the real addresses.
	nine := make([]netip.Addr, 9)
	for i := range nine {
		nine[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
	}
	fragment := func(f []byte) []byte {
		binary.BigEndian.PutUint16(f[14+6:], 0x2000) // MF
		return f
	}
	// A hop-by-hop options header between the IPv6 header and UDP (its
	// contents are not built: the program must not look past it).
	extHeader := func(f []byte) []byte {
		f[14+6] = 0
		return f
	}
	for _, c := range []struct {
		name  string
		frame []byte
	}{
		{"unwatched host", udpFrame(vipTestDNS, vipTestPod, 53, 40000,
			dnsResponse(t, vipTestNoHost, dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, vipTestNoHost, vipTestReal[0])), true)},
		{"not from port 53", udpFrame(vipTestDNS, vipTestPod, 5353, 40000,
			dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal[0])), true)},
		{"NXDOMAIN", udpFrame(vipTestDNS, vipTestPod, 53, 40000,
			dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil), true)},
		{"A records in the answer to an AAAA question", udpFrame(vipTestDNS, vipTestPod, 53, 40000,
			dnsResponse(t, "api.example.com", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal[0])), true)},
		{"TXT question", udpFrame(vipTestDNS, vipTestPod, 53, 40000,
			dnsResponse(t, "api.example.com", dnsmessage.TypeTXT, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal[0])), true)},
		{"IPv6 extension header", extHeader(udpFrame(vipTestDNS6, vipTestPod6, 53, 40000,
			dnsResponse(t, "api.example.com", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal6[0])), true))},
		{"more A records than DNS_MAX_ADDR_RECORDS", udpFrame(vipTestDNS, vipTestPod, 53, 40000,
			dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", nine...)), true)},
		{"IP fragment", fragment(udpFrame(vipTestDNS, vipTestPod, 53, 40000,
			dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal[0])), true))},
	} {
		t.Run(c.name, func(t *testing.T) {
			clearUpstreams(t, objs)
			if out := runTC(t, prog, c.frame); !bytes.Equal(out, c.frame) {
				t.Error("packet changed")
			}
			for _, fake := range []netip.Addr{vipTestFake, vipTestFake6} {
				if _, ok := readUpstream(t, objs, fake); ok {
					t.Errorf("vip_upstream written for %s", fake)
				}
			}
		})
	}

	t.Run("trusted DNS servers", func(t *testing.T) {
		on := uint8(1)
		if err := objs.DnsWhitelistEnabled.Update(uint32(0), &on, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for _, ip := range []netip.Addr{vipTestDNS, vipTestDNS6} {
			key := dnsIPKey{IP: ip.As16()}
			if err := objs.TrustedDnsServers.Update(&key, &on, ciliumebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = objs.TrustedDnsServers.Delete(&key) })
		}
		t.Cleanup(func() {
			off := uint8(0)
			_ = objs.DnsWhitelistEnabled.Update(uint32(0), &off, ciliumebpf.UpdateAny)
		})
		msg := dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal[0]))
		for _, c := range []struct{ trusted, untrusted, pod netip.Addr }{
			{vipTestDNS, netip.MustParseAddr("10.42.0.99"), vipTestPod},
			{vipTestDNS6, netip.MustParseAddr("fd42::99"), vipTestPod6},
		} {
			untrusted := udpFrame(c.untrusted, c.pod, 53, 40000, msg, true)
			if out := runTC(t, prog, untrusted); !bytes.Equal(out, untrusted) {
				t.Errorf("answer from the untrusted %s rewritten", c.untrusted)
			}
			out := runTC(t, prog, udpFrame(c.trusted, c.pod, 53, 40000, msg, true))
			if got := answerAddrs(t, out); len(got) != 1 || got[0] != vipTestFake {
				t.Errorf("answer from the trusted %s: %v", c.trusted, got)
			}
		}
	})
}

// TestVirtualIPConnectRedirect runs vip_connect4/6 / vip_getpeername4/6 on
// the kernel's connect path: a process in a cgroup with them attached
// connects to fake IPs and fake IPv6s.
func TestVirtualIPConnectRedirect(t *testing.T) {
	objs := loadVirtualIPObjects(t)
	path, _, cleanup, err := cgroups.CreateTransient("", fmt.Sprintf("vip-test-%d", os.Getpid()))
	if err != nil {
		t.Skipf("cannot create a cgroup: %v", err)
	}
	t.Cleanup(func() { _ = cleanup() })
	for _, a := range []struct {
		prog   *ciliumebpf.Program
		attach ciliumebpf.AttachType
	}{
		{objs.VipConnect4, ciliumebpf.AttachCGroupInet4Connect},
		{objs.VipConnect6, ciliumebpf.AttachCGroupInet6Connect},
		{objs.VipGetpeername4, ciliumebpf.AttachCgroupInet4GetPeername},
		{objs.VipGetpeername6, ciliumebpf.AttachCgroupInet6GetPeername},
	} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: path, Attach: a.attach, Program: a.prog})
		if err != nil {
			t.Fatalf("attaching %s: %v", a.attach, err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}

	// One port for the IPv4 and the IPv6 loopback listener.
	ln6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	t.Cleanup(func() { _ = ln6.Close() })
	port := ln6.Addr().(*net.TCPAddr).Port
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	for _, l := range []net.Listener{ln, ln6} {
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}

	// vipTestFake / vipTestFake6 lead to the listeners; vipTestFake2 /
	// vipTestFake62 are reserved but no answer was recorded for them;
	// .7 / ::7 are not reserved. vipTestFake3's upstream is of the wrong
	// family.
	vipTestFake3 := netip.MustParseAddr("198.18.0.8")
	for _, ip := range []netip.Addr{vipTestFake, vipTestFake2, vipTestFake6, vipTestFake62, vipTestFake3} {
		key := dnsIPKey{IP: ip.As16()}
		val := vipIPValue(vipEntry{Host: "api.example.com"})
		if err := objs.VipIpHost.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	for fake, real := range map[netip.Addr]netip.Addr{
		vipTestFake:  netip.MustParseAddr("127.0.0.1"),
		vipTestFake6: netip.MustParseAddr("::1"),
		vipTestFake3: netip.MustParseAddr("::1"),
	} {
		var up vipUpstreamVal
		up.Slot[0] = vipUpstreamSlot{IP: real.As16(), ExpiresAt: bootNanos(t) + uint64(time.Minute)}
		key := dnsIPKey{IP: fake.As16()}
		if err := objs.VipUpstream.Update(&key, &up, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}

	for _, c := range []struct {
		addr     netip.Addr
		families []string
		want     string
		host     string // recorded for the socket in vip_sock_host
	}{
		// From an AF_INET socket, and from an AF_INET6 one through the
		// v4-mapped address (connect6 / getpeername6).
		{vipTestFake, []string{"4", "6"}, fmt.Sprintf("connected %s:%d", vipTestFake, port), "api.example.com"},
		{vipTestFake2, []string{"4", "6"}, "operation not permitted", ""},
		{netip.MustParseAddr("198.18.0.7"), []string{"4", "6"}, "operation not permitted", ""},
		{vipTestFake3, []string{"4", "6"}, "operation not permitted", ""},
		// Outside the range: left alone.
		{netip.MustParseAddr("127.0.0.1"), []string{"4", "6"}, fmt.Sprintf("connected 127.0.0.1:%d", port), ""},
		// IPv6, from an AF_INET6 socket.
		{vipTestFake6, []string{"6"}, fmt.Sprintf("connected [%s]:%d", vipTestFake6, port), "api.example.com"},
		{vipTestFake62, []string{"6"}, "operation not permitted", ""},
		{netip.MustParseAddr("2001:2::7"), []string{"6"}, "operation not permitted", ""},
		{netip.MustParseAddr("::1"), []string{"6"}, fmt.Sprintf("connected [::1]:%d", port), ""},
	} {
		for _, family := range c.families {
			out := connectFromCgroup(t, path, family, netip.AddrPortFrom(c.addr, uint16(port)), netip.AddrPort{})
			if !strings.Contains(out, c.want) {
				t.Errorf("AF_INET%s connect to %s: %q, want %q", family, c.addr, out, c.want)
			}
			if got := sockHost(t, objs, out); got != c.host {
				t.Errorf("AF_INET%s connect to %s: socket host %q, want %q", family, c.addr, got, c.host)
			}
		}
	}

	// A socket whose connect to a fake IP failed and that then connects
	// elsewhere loses the host (nothing listens on the fake IP's port 1).
	for _, c := range []struct {
		family       string
		fake, direct netip.Addr
	}{
		{"4", vipTestFake, netip.MustParseAddr("127.0.0.1")},
		{"6", vipTestFake, netip.MustParseAddr("127.0.0.1")},
		{"6", vipTestFake6, netip.MustParseAddr("::1")},
	} {
		direct := netip.AddrPortFrom(c.direct, uint16(port))
		out := connectFromCgroup(t, path, c.family, netip.AddrPortFrom(c.fake, 1), direct)
		if !strings.Contains(out, "failed: connection refused") || !strings.Contains(out, "then connected "+direct.String()) {
			t.Fatalf("AF_INET%s connect to %s:1, then %s: %q", c.family, c.fake, direct, out)
		}
		if got := sockHost(t, objs, out); got != "" {
			t.Errorf("AF_INET%s reconnected socket kept socket host %q", c.family, got)
		}
	}
}

// sockHost returns the host vip_sock_host holds for the socket whose cookie
// the connect helper reported in out, "" when none.
func sockHost(t *testing.T, objs *tlsuprobeObjects, out string) string {
	t.Helper()
	var cookie uint64
	for _, line := range strings.Split(out, "\n") {
		if _, err := fmt.Sscanf(line, "cookie %d", &cookie); err == nil {
			break
		}
	}
	if cookie == 0 {
		t.Fatalf("no socket cookie in %q", out)
	}
	var host [maxHostLen]byte
	if err := objs.VipSockHost.Lookup(&cookie, &host); err != nil {
		if errors.Is(err, ciliumebpf.ErrKeyNotExist) {
			return ""
		}
		t.Fatal(err)
	}
	return vipHostString(host, maxHostLen)
}

// connectFromCgroup connects to addr from a child process started in the
// cgroup at path, with an AF_INET or (family "6") AF_INET6 socket, then, if
// then is valid, connects the same socket to it, and returns what it
// reports.
func connectFromCgroup(t *testing.T, path, family string, addr, then netip.AddrPort) string {
	t.Helper()
	cg, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cg.Close() }()
	cmd := exec.Command(os.Args[0], "-test.run=^TestVirtualIPConnectHelper$")
	cmd.Env = append(os.Environ(), "KLOAK_VIP_CONNECT="+addr.String(), "KLOAK_VIP_CONNECT_FAMILY="+family)
	if then.IsValid() {
		cmd.Env = append(cmd.Env, "KLOAK_VIP_CONNECT_THEN="+then.String())
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	return string(out)
}

// TestVirtualIPConnectHelper is the child process of connectFromCgroup. It
// reports its socket's cookie and the peer getpeername() returns.
func TestVirtualIPConnectHelper(t *testing.T) {
	addr := os.Getenv("KLOAK_VIP_CONNECT")
	if addr == "" {
		t.Skip("helper process for TestVirtualIPConnectRedirect")
	}
	six := os.Getenv("KLOAK_VIP_CONNECT_FAMILY") == "6"
	sockaddr := func(ap netip.AddrPort) unix.Sockaddr {
		if six {
			return &unix.SockaddrInet6{Addr: netip.AddrFrom16(ap.Addr().As16()).As16(), Port: int(ap.Port())}
		}
		return &unix.SockaddrInet4{Addr: ap.Addr().As4(), Port: int(ap.Port())}
	}
	domain := unix.AF_INET
	if six {
		// Go's net package dials IPv4 addresses with AF_INET sockets only.
		domain = unix.AF_INET6
	}
	fd, err := unix.Socket(domain, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("cookie", cookie)
	// A connect left on a fake IP would hang on the unrouted range.
	tv := unix.NsecToTimeval((5 * time.Second).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	err = unix.Connect(fd, sockaddr(netip.MustParseAddrPort(addr)))
	if then := os.Getenv("KLOAK_VIP_CONNECT_THEN"); then != "" {
		if err != nil {
			fmt.Println("failed:", err)
		}
		if err = unix.Connect(fd, sockaddr(netip.MustParseAddrPort(then))); err != nil {
			fmt.Println("then failed:", err)
			return
		}
		fmt.Print("then ")
	} else if err != nil {
		fmt.Println("failed:", err)
		return
	}
	peer, err := unix.Getpeername(fd)
	if err != nil {
		t.Fatal(err)
	}
	switch p := peer.(type) {
	case *unix.SockaddrInet4:
		fmt.Printf("connected %s\n", netip.AddrPortFrom(netip.AddrFrom4(p.Addr), uint16(p.Port)))
	case *unix.SockaddrInet6:
		fmt.Printf("connected %s\n", netip.AddrPortFrom(netip.AddrFrom16(p.Addr).Unmap(), uint16(p.Port)))
	}
}
