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
	vipTestDNS    = netip.MustParseAddr("10.43.0.10")
	vipTestPod    = netip.MustParseAddr("10.42.0.7")
	vipTestReal   = []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")}
	vipTestHosts  = map[string]netip.Addr{"api.example.com": vipTestFake, "apis.example.com": vipTestFake2}
	vipTestNoHost = "other.example.com"
)

// loadVirtualIPObjects loads the BPF objects with the virtual IP range of
// the tests configured, vipTestHosts watched, and vipTestPod granted them.
func loadVirtualIPObjects(t *testing.T) *tlsuprobeObjects {
	t.Helper()
	objs := loadTestObjects(t)
	cfg := vipConfig(testVIPRange)
	if err := objs.VipConfig.Update(uint32(0), &cfg, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for host, ip := range vipTestHosts {
		key := vipHostKey(host)
		val := vipHostVal{IP4: ip.As4()}
		if err := objs.VipHostIp.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		putPodHost(t, objs, vipTestPod, host)
	}
	return objs
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

func aRecords(t *testing.T, name string, ips ...netip.Addr) func(*dnsmessage.Builder) {
	return func(b *dnsmessage.Builder) {
		for _, ip := range ips {
			h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name + "."), Class: dnsmessage.ClassINET, TTL: 30}
			if err := b.AResource(h, dnsmessage.AResource{A: ip.As4()}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// udpFrame wraps payload in Ethernet, IPv4 and UDP headers. A zero
// checksum is sent when withCsum is false.
func udpFrame(src, dst netip.Addr, sport, dport uint16, payload []byte, withCsum bool) []byte {
	udpLen := 8 + len(payload)
	f := make([]byte, 14+20+udpLen)
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	ip := f[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+udpLen))
	ip[8] = 64
	ip[9] = unix.IPPROTO_UDP
	copy(ip[12:16], src.AsSlice())
	copy(ip[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(ip[10:], ^onesSum(0, ip))
	udp := f[34:]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], payload)
	if withCsum {
		c := ^onesSum(udpPseudoSum(ip, udpLen), udp)
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

func udpPseudoSum(ip []byte, udpLen int) uint32 {
	var s uint32
	for i := 12; i < 20; i += 2 {
		s += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	return s + unix.IPPROTO_UDP + uint32(udpLen)
}

// udpChecksumOK verifies the UDP checksum of a frame built by udpFrame.
func udpChecksumOK(f []byte) bool {
	ip, udp := f[14:34], f[34:]
	if binary.BigEndian.Uint16(udp[6:]) == 0 {
		return true
	}
	return onesSum(udpPseudoSum(ip, len(udp)), udp) == 0xFFFF
}

// answerAddrs returns the A record addresses of the DNS message in a frame.
func answerAddrs(t *testing.T, f []byte) []netip.Addr {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(f[42:]); err != nil {
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
		if h.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				t.Fatal(err)
			}
			continue
		}
		a, err := p.AResource()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, netip.AddrFrom4(a.A))
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
	for _, ip := range vipTestHosts {
		key := dnsIPKey{IP: ip.As16()}
		if err := objs.VipUpstream.Delete(&key); err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
			t.Fatal(err)
		}
	}
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

	// The A records of a watched host's answer become its fake IP, behind a
	// CNAME chain too, and the real addresses are recorded for the connect
	// redirect. The two hosts' names differ in length by one byte, so their
	// records start at an odd and an even offset (checksum update).
	for _, host := range []string{"api.example.com", "apis.example.com"} {
		t.Run(host, func(t *testing.T) {
			clearUpstreams(t, objs)
			before := bootNanos(t)
			msg := dnsResponse(t, host, dnsmessage.TypeA, dnsmessage.RCodeSuccess, func(b *dnsmessage.Builder) {
				h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(host + "."), Class: dnsmessage.ClassINET, TTL: 300}
				if err := b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.example.net.")}); err != nil {
					t.Fatal(err)
				}
				aRecords(t, "edge.example.net", vipTestReal...)(b)
			})
			out := runTC(t, prog, udpFrame(vipTestDNS, vipTestPod, 53, 40000, msg, true))
			fake := vipTestHosts[host]
			if got := answerAddrs(t, out); len(got) != 2 || got[0] != fake || got[1] != fake {
				t.Errorf("A records after rewrite: %v, want 2 x %s", got, fake)
			}
			if !udpChecksumOK(out) {
				t.Error("UDP checksum wrong after rewrite")
			}
			up, ok := readUpstream(t, objs, fake)
			if !ok {
				t.Fatal("no vip_upstream entry")
			}
			for i, want := range vipTestReal {
				s := up.Slot[i]
				if netip.AddrFrom4(s.IP4) != want {
					t.Errorf("slot %d = %v, want %s", i, s.IP4, want)
				}
				// TTL 30 s from now.
				if s.ExpiresAt < before+29*uint64(time.Second) || s.ExpiresAt > bootNanos(t)+30*uint64(time.Second) {
					t.Errorf("slot %d expires at %d, now %d", i, s.ExpiresAt, before)
				}
			}
		})
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
		clearUpstreams(t, objs)
		msg := dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestFake))
		in := udpFrame(vipTestDNS, vipTestPod, 53, 40000, msg, true)
		if out := runTC(t, prog, in); !bytes.Equal(out, in) {
			t.Error("answer changed")
		}
		if _, ok := readUpstream(t, objs, vipTestFake); ok {
			t.Error("fake IP recorded as its own upstream")
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
		} {
			t.Run(c.name, func(t *testing.T) {
				clearUpstreams(t, objs)
				msg := dnsResponse(t, c.host, dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, c.host, vipTestReal[0]))
				in := udpFrame(vipTestDNS, c.pod, 53, 40000, msg, true)
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
		{"AAAA answer", udpFrame(vipTestDNS, vipTestPod, 53, 40000,
			dnsResponse(t, "api.example.com", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, func(b *dnsmessage.Builder) {
				h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("api.example.com."), Class: dnsmessage.ClassINET, TTL: 30}
				if err := b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}); err != nil {
					t.Fatal(err)
				}
			}), true)},
		{"more A records than DNS_MAX_A_RECORDS", udpFrame(vipTestDNS, vipTestPod, 53, 40000,
			dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", nine...)), true)},
		{"IP fragment", fragment(udpFrame(vipTestDNS, vipTestPod, 53, 40000,
			dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal[0])), true))},
	} {
		t.Run(c.name, func(t *testing.T) {
			clearUpstreams(t, objs)
			if out := runTC(t, prog, c.frame); !bytes.Equal(out, c.frame) {
				t.Error("packet changed")
			}
			if _, ok := readUpstream(t, objs, vipTestFake); ok {
				t.Error("vip_upstream written")
			}
		})
	}

	t.Run("trusted DNS servers", func(t *testing.T) {
		on := uint8(1)
		if err := objs.DnsWhitelistEnabled.Update(uint32(0), &on, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		key := dnsIPKey{IP: vipTestDNS.As16()}
		if err := objs.TrustedDnsServers.Update(&key, &on, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			off := uint8(0)
			_ = objs.DnsWhitelistEnabled.Update(uint32(0), &off, ciliumebpf.UpdateAny)
			_ = objs.TrustedDnsServers.Delete(&key)
		})
		msg := dnsResponse(t, "api.example.com", dnsmessage.TypeA, dnsmessage.RCodeSuccess, aRecords(t, "api.example.com", vipTestReal[0]))
		untrusted := udpFrame(netip.MustParseAddr("10.42.0.99"), vipTestPod, 53, 40000, msg, true)
		if out := runTC(t, prog, untrusted); !bytes.Equal(out, untrusted) {
			t.Error("answer from an untrusted server rewritten")
		}
		out := runTC(t, prog, udpFrame(vipTestDNS, vipTestPod, 53, 40000, msg, true))
		if got := answerAddrs(t, out); len(got) != 1 || got[0] != vipTestFake {
			t.Errorf("answer from the trusted server: %v", got)
		}
	})
}

// TestVirtualIPConnectRedirect runs vip_connect4 / vip_getpeername4 on the
// kernel's connect path: a process in a cgroup with them attached connects to
// fake IPs.
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

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	// vipTestFake leads to the listener; vipTestFake2 is reserved but no
	// answer was recorded for it; .7 is not reserved.
	for _, ip := range []netip.Addr{vipTestFake, vipTestFake2} {
		key := dnsIPKey{IP: ip.As16()}
		val := vipIPValue(vipEntry{Host: "api.example.com"})
		if err := objs.VipIpHost.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	var up vipUpstreamVal
	up.Slot[0] = vipUpstreamSlot{IP4: [4]byte{127, 0, 0, 1}, ExpiresAt: bootNanos(t) + uint64(time.Minute)}
	key := dnsIPKey{IP: vipTestFake.As16()}
	if err := objs.VipUpstream.Update(&key, &up, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		addr netip.Addr
		want string
	}{
		{vipTestFake, fmt.Sprintf("connected %s:%d", vipTestFake, port)},
		{vipTestFake2, "operation not permitted"},
		{netip.MustParseAddr("198.18.0.7"), "operation not permitted"},
		// Outside the range: left alone.
		{netip.MustParseAddr("127.0.0.1"), fmt.Sprintf("connected 127.0.0.1:%d", port)},
	} {
		// From an AF_INET socket, and from an AF_INET6 one through the
		// v4-mapped address (connect6 / getpeername6).
		for _, family := range []string{"4", "6"} {
			out := connectFromCgroup(t, path, family, netip.AddrPortFrom(c.addr, uint16(port)))
			if !strings.Contains(out, c.want) {
				t.Errorf("AF_INET%s connect to %s: %q, want %q", family, c.addr, out, c.want)
			}
		}
	}
}

// connectFromCgroup connects to addr from a child process started in the
// cgroup at path, with an AF_INET or (family "6") AF_INET6 socket, and
// returns what it reports.
func connectFromCgroup(t *testing.T, path, family string, addr netip.AddrPort) string {
	t.Helper()
	cg, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cg.Close() }()
	cmd := exec.Command(os.Args[0], "-test.run=^TestVirtualIPConnectHelper$")
	cmd.Env = append(os.Environ(), "KLOAK_VIP_CONNECT="+addr.String(), "KLOAK_VIP_CONNECT_FAMILY="+family)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	return string(out)
}

// TestVirtualIPConnectHelper is the child process of connectFromCgroup. It
// reports the peer getpeername() returns.
func TestVirtualIPConnectHelper(t *testing.T) {
	addr := os.Getenv("KLOAK_VIP_CONNECT")
	if addr == "" {
		t.Skip("helper process for TestVirtualIPConnectRedirect")
	}
	ap := netip.MustParseAddrPort(addr)
	domain := unix.AF_INET
	var sa unix.Sockaddr = &unix.SockaddrInet4{Addr: ap.Addr().As4(), Port: int(ap.Port())}
	if os.Getenv("KLOAK_VIP_CONNECT_FAMILY") == "6" {
		// Go's net package dials IPv4 addresses with AF_INET sockets only.
		domain = unix.AF_INET6
		sa = &unix.SockaddrInet6{Addr: netip.AddrFrom16(ap.Addr().As16()).As16(), Port: int(ap.Port())}
	}
	fd, err := unix.Socket(domain, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	// A connect left on a fake IP would hang on the unrouted range.
	tv := unix.NsecToTimeval((5 * time.Second).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(fd, sa); err != nil {
		fmt.Println("failed:", err)
		return
	}
	peer, err := unix.Getpeername(fd)
	if err != nil {
		t.Fatal(err)
	}
	switch p := peer.(type) {
	case *unix.SockaddrInet4:
		fmt.Printf("connected %s:%d\n", netip.AddrFrom4(p.Addr), p.Port)
	case *unix.SockaddrInet6:
		fmt.Printf("connected %s:%d\n", netip.AddrFrom16(p.Addr).Unmap(), p.Port)
	}
}
