//go:build linux

package ebpf

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"

	"github.com/spinningfactory/kloak/pkg/cgroups"
)

// chainGoTLS mirrors CHAIN_GO_TLS in tls_uprobe.c.
const chainGoTLS = 2

// TestGoAEADTypeCheckKprobe runs the tcp_sendmsg kprobe on TLS writes from
// this (Go) process, staged as the Go uprobe would stage them, and checks the
// AEAD type check: the kprobe bridges a write to tc_pending only when the
// connection's AEAD is one of Go's own AES-GCM types. A ChaCha20-Poly1305
// connection, or an AES-GCM one whose type is not in the allowed list (as a
// BoringCrypto or OpenSSL-backed AEAD would be), gets no H and no patch.
// Needs root (or CAP_BPF + CAP_PERFMON); skipped otherwise.
func TestGoAEADTypeCheckKprobe(t *testing.T) {
	objs := loadTestObjects(t)
	kp, err := link.Kprobe("tcp_sendmsg", objs.BpfKprobeTcpSendmsg, nil)
	if err != nil {
		t.Skipf("cannot attach kprobe tcp_sendmsg: %v", err)
	}
	defer func() { _ = kp.Close() }()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, offsets, err := DetectGoTLSOffsets(exe)
	if err != nil {
		t.Skipf("Go TLS offsets of the test binary: %v", err)
	}
	info, err := inspectGoCrypto(exe)
	if err != nil {
		t.Fatalf("inspectGoCrypto: %v", err)
	}
	allowed, err := goAEADSealOffsets(os.Getpid(), info)
	if err != nil {
		t.Fatalf("goAEADSealOffsets: %v", err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(exe, &st); err != nil {
		t.Fatal(err)
	}
	cgroupID := bpfCgroupID(t)
	binKey := tlsuprobeTlsBinaryKey{CgroupId: cgroupID, ExeInode: st.Ino}

	shadow := []byte("kl::GoAEADtypeCheck0")
	var sk secretKey
	copy(sk.Prefix[:], shadow)
	var sv secretValue
	sv.Len = uint32(len(shadow))
	copy(sv.RealSecret[:], "real-GoAEADtypeCheck")
	if err := objs.SecretMap.Update(&sk, &sv, 0); err != nil {
		t.Fatal(err)
	}
	var bk tlsuprobeSecretKey
	for i, b := range sk.Prefix {
		bk.Prefix[i] = int8(b)
	}

	denyIdx := uint32(slices.Index(debugCounterNames, "go_aead_type_deny"))
	addr := startQuietTLSServer(t)
	tgid := uint32(os.Getpid())

	for _, c := range []struct {
		name   string
		cfg    *tls.Config
		seal   []uint32
		bridge bool
	}{
		{"TLS1.3 AES-GCM", &tls.Config{MinVersion: tls.VersionTLS13}, allowed, true},
		{"TLS1.2 AES-128-GCM", &tls.Config{MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}, allowed, true},
		{"TLS1.2 ChaCha20-Poly1305", &tls.Config{MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}}, allowed, false},
		// As for a BoringCrypto or OpenSSL AEAD: an AES-GCM whose Seal is not allowed.
		{"TLS1.3 AES-GCM, type not allowed", &tls.Config{MinVersion: tls.VersionTLS13}, []uint32{1}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := offsets
			o.setAEADSealOffsets(c.seal)
			if err := objs.GoTlsOffsetConfig.Update(&binKey, &o, 0); err != nil {
				t.Fatal(err)
			}
			cfg := c.cfg.Clone()
			cfg.InsecureSkipVerify = true
			conn, err := tls.Dial("tcp", addr, cfg)
			if err != nil {
				t.Fatalf("TLS dial: %v", err)
			}
			defer func() { _ = conn.Close() }()

			var pv tlsuprobeXorPendingVal
			pv.SslPtr = uint64(uintptr(unsafe.Pointer(conn)))
			pv.Tgid, pv.PatchCount, pv.Active, pv.ChainType = tgid, 1, 1, chainGoTLS
			pv.Patches[0].SecretLen = uint32(len(shadow))
			pv.Patches[0].Key = bk
			pv.PlaintextLen = uint32(len(shadow))
			for i := range shadow {
				pv.Patches[0].XorDelta[i] = shadow[i] ^ sv.RealSecret[i]
			}
			denyBefore := debugCounter(t, objs, denyIdx)
			if err := objs.XorPending.Update(tgid, &pv, 0); err != nil {
				t.Fatal(err)
			}
			_, werr := conn.Write(shadow)
			_ = objs.XorPending.Delete(tgid)
			if werr != nil {
				t.Fatalf("TLS write: %v", werr)
			}
			runtime.KeepAlive(conn)

			var port [2]byte
			binary.BigEndian.PutUint16(port[:], uint16(conn.LocalAddr().(*net.TCPAddr).Port))
			dk := tlsuprobeTcDestKey{
				DstIp:    netip.MustParseAddr("127.0.0.1").As16(),
				SrcPort:  binary.NativeEndian.Uint16(port[:]),
				CgroupId: cgroupID,
			}
			var tv tlsuprobeTcPendingVal
			bridged := objs.TcPending.Lookup(&dk, &tv) == nil
			_ = objs.TcPending.Delete(&dk)
			denied := debugCounter(t, objs, denyIdx) - denyBefore

			t.Logf("suite %s: bridged=%v type denials=%d", tls.CipherSuiteName(conn.ConnectionState().CipherSuite), bridged, denied)
			if bridged != c.bridge {
				t.Errorf("bridged to tc_pending = %v, want %v", bridged, c.bridge)
			}
			if wantDenied := uint64(0); !c.bridge {
				wantDenied = 1
				if denied != wantDenied {
					t.Errorf("go_aead_type_deny went up by %d, want %d", denied, wantDenied)
				}
			} else if denied != 0 {
				t.Errorf("go_aead_type_deny went up by %d for an allowed type", denied)
			}
		})
	}
}

// startQuietTLSServer accepts TLS connections and only reads from them: a
// write from this process after the client's handshake would reach the
// kprobe as the staged write. So no session tickets, and connections are
// closed under TLS, without a close_notify alert.
func startQuietTLSServer(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:           []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		SessionTicketsDisabled: true,
	})
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
			go func() {
				defer func() { _ = c.(*tls.Conn).NetConn().Close() }()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// debugCounter sums one debug_counters slot over all CPUs.
func debugCounter(t *testing.T, objs *tlsuprobeObjects, idx uint32) uint64 {
	t.Helper()
	var vals []uint64
	if err := objs.DebugCounters.Lookup(idx, &vals); err != nil {
		t.Fatal(err)
	}
	var sum uint64
	for _, v := range vals {
		sum += v
	}
	return sum
}

// bpfCgroupID returns the cgroup v2 ID that bpf_get_current_cgroup_id
// reports for this process: its cgroup2 path resolved under wherever the
// cgroup2 hierarchy is mounted (/sys/fs/cgroup on a unified host,
// /sys/fs/cgroup/unified on a hybrid one).
func bpfCgroupID(t *testing.T) uint64 {
	t.Helper()
	mounts, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mounts.Close() }()
	var mnt string
	sc := bufio.NewScanner(mounts)
	for sc.Scan() {
		// ID parent maj:min root mountpoint options... - fstype source superopts
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		if f := strings.Fields(pre); ok && len(f) >= 5 && strings.HasPrefix(post, "cgroup2 ") {
			mnt = f[4]
			break
		}
	}
	if mnt == "" {
		t.Skip("no cgroup2 mount")
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			id, err := cgroups.GetCgroupInodeFromPath(filepath.Join(mnt, p))
			if err != nil {
				t.Skipf("cgroup ID: %v", err)
			}
			return id
		}
	}
	t.Skip("no cgroup2 membership")
	return 0
}
