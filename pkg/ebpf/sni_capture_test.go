//go:build linux

package ebpf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
)

// Mirrors of SNI_STATUS_* in helpers.h.
const (
	sniStatusSeen   = 1
	sniStatusAbsent = 2
)

// sniStateVal must match struct sni_state_val in tls_uprobe.c.
type sniStateVal struct {
	Status uint32
	Len    uint32
	SNI    [maxHostLen]byte
}

// TestSNICaptureKernel attaches the SNI capture kprobe and the socket-state
// tracepoint, makes real TLS connections from this process, and checks what
// lands in sni_state. Needs root (or CAP_BPF + CAP_PERFMON) and a kernel
// with BTF; skipped otherwise.
func TestSNICaptureKernel(t *testing.T) {
	objs := loadTestObjects(t)

	kp, err := link.Kprobe("tcp_sendmsg", objs.BpfKprobeTcpSendmsgSni, nil)
	if err != nil {
		t.Skipf("cannot attach kprobe tcp_sendmsg: %v", err)
	}
	defer func() { _ = kp.Close() }()
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TpInetSockSetState, nil)
	if err != nil {
		t.Skipf("cannot attach tracepoint sock/inet_sock_set_state: %v", err)
	}
	defer func() { _ = tp.Close() }()

	tgid, tracked := uint32(os.Getpid()), uint8(1)
	if err := objs.TrackedTgids.Update(tgid, &tracked, 0); err != nil {
		t.Fatalf("tracking own tgid: %v", err)
	}

	addr := startTLSServer(t)

	// Uppercase + trailing dot: stored lowercased, without the dot.
	conn := dialTLS(t, addr, "API.Example.com.")
	if !waitSNIState(t, objs, func(v sniStateVal) bool {
		return v.Status == sniStatusSeen && hostString(v.SNI) == "api.example.com" && v.Len == 15
	}) {
		t.Fatalf("no SEEN api.example.com entry in sni_state: %v", dumpSNIState(t, objs))
	}

	// Closing the connection reaches TCP_CLOSE, which forgets the socket.
	if err := conn.Close(); err != nil {
		t.Fatalf("closing TLS connection: %v", err)
	}
	if !waitSNIStateGone(t, objs, func(v sniStateVal) bool {
		return v.Status == sniStatusSeen && hostString(v.SNI) == "api.example.com"
	}) {
		t.Fatalf("sni_state entry not removed after close: %v", dumpSNIState(t, objs))
	}

	// Go sends no SNI when ServerName is empty.
	conn = dialTLS(t, addr, "")
	defer func() { _ = conn.Close() }()
	if !waitSNIState(t, objs, func(v sniStateVal) bool { return v.Status == sniStatusAbsent }) {
		t.Fatalf("no ABSENT entry in sni_state: %v", dumpSNIState(t, objs))
	}
}

func startTLSServer(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"api.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
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
				defer func() { _ = c.Close() }()
				_ = c.(*tls.Conn).Handshake()
				_, _ = c.Read(make([]byte, 1))
			}()
		}
	}()
	return ln.Addr().String()
}

func dialTLS(t *testing.T, addr, serverName string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS dial (SNI %q): %v", serverName, err)
	}
	return conn
}

func hostString(b [maxHostLen]byte) string {
	if n := bytes.IndexByte(b[:], 0); n >= 0 {
		return string(b[:n])
	}
	return string(b[:])
}

func sniStateValues(t *testing.T, objs *tlsuprobeObjects) []sniStateVal {
	t.Helper()
	var (
		k    uint64
		v    sniStateVal
		vals []sniStateVal
	)
	iter := objs.SniState.Iterate()
	for iter.Next(&k, &v) {
		vals = append(vals, v)
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterating sni_state: %v", err)
	}
	return vals
}

func dumpSNIState(t *testing.T, objs *tlsuprobeObjects) []string {
	var out []string
	for _, v := range sniStateValues(t, objs) {
		out = append(out, fmt.Sprintf("%q/status=%d", hostString(v.SNI), v.Status))
	}
	return out
}

func waitSNIState(t *testing.T, objs *tlsuprobeObjects, match func(sniStateVal) bool) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		for _, v := range sniStateValues(t, objs) {
			if match(v) {
				return true
			}
		}
	}
	return false
}

func waitSNIStateGone(t *testing.T, objs *tlsuprobeObjects, match func(sniStateVal) bool) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		found := false
		for _, v := range sniStateValues(t, objs) {
			found = found || match(v)
		}
		if !found {
			return true
		}
	}
	return false
}
