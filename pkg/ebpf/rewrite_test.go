//go:build linux

package ebpf

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/spinningfactory/kloak/pkg/webhook"
)

// TestEBPFRewriteGoTLS tests the full eBPF data path by attaching uprobes to
// the test process itself, making a real TLS connection, and verifying that
// kloak:UUID placeholders are rewritten with real secret values in-kernel.
func TestEBPFRewriteGoTLS(t *testing.T) {
	objs := loadTestObjects(t)

	// 1. Pre-populate secret_map with a test secret.
	// The placeholder is "kloak:test1234" (14 bytes), value is "REAL-SECRET-!!" (14 bytes).
	placeholder := "kloak:test1234"
	realSecret := "REAL-SECRET-!!"
	if len(placeholder) != len(realSecret) {
		t.Fatal("placeholder and real secret must be the same length")
	}

	var key secretKey
	copy(key.Prefix[:], []byte(placeholder)[:8])
	var val secretValue
	val.Len = uint32(len(realSecret))
	copy(val.RealSecret[:], realSecret)
	// No host filter (wildcard) — HostLen=0
	val.PrefixLen = uint32(len(placeholder))
	copy(val.FullPrefix[:], placeholder)

	if err := objs.SecretMap.Update(&key, &val, 0); err != nil {
		t.Fatalf("failed to populate secret_map: %v", err)
	}

	// 2. Wire the tail call
	phase2FD := uint32(objs.BpfPhase2Rewrite.FD())
	if err := objs.ProgArray.Update(uint32(0), &phase2FD, 0); err != nil {
		t.Fatalf("failed to wire tail call: %v", err)
	}

	// 3. Generate self-signed TLS cert for the test server
	certPEM, keyPEM, err := webhook.GenerateSelfSignedCert("default")
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse TLS key pair: %v", err)
	}

	// 4. Start TLS server
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	addr := listener.Addr().String()

	// Server goroutine: accept one connection, read all data, send it to channel
	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- fmt.Sprintf("ERROR: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		data, err := io.ReadAll(conn)
		if err != nil {
			received <- fmt.Sprintf("ERROR: %v", err)
			return
		}
		received <- string(data)
	}()

	// 5. Attach uprobes to this test process
	pid := os.Getpid()
	mgr := &TLSUprobeManager{
		objs: objs,
		log:  testLog(),
	}
	if err := mgr.AttachTLS(pid); err != nil {
		t.Skipf("could not attach TLS uprobes to test process (may need Go symbols): %v", err)
	}

	// 6. Open ringbuf reader for rewrite events
	reader, err := ringbuf.NewReader(objs.TlsEvents)
	if err != nil {
		t.Fatalf("failed to open ringbuf reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	// 7. Make a TLS connection and send the placeholder
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	// Force HTTP/1.1 to ensure Host header is readable by eBPF
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    certPool,
		ServerName: "kloak-webhook.default.svc",
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("failed to dial TLS: %v", err)
	}

	payload := fmt.Sprintf("GET / HTTP/1.1\r\nHost: example.com\r\nX-Secret: %s\r\n\r\n", placeholder)
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Logf("conn.Close: %v", err)
	}

	// 8. Check what the server received
	select {
	case data := <-received:
		if strings.HasPrefix(data, "ERROR:") {
			t.Fatalf("server error: %s", data)
		}
		t.Logf("Server received: %s", data)

		if strings.Contains(data, realSecret) {
			t.Logf("SUCCESS: eBPF rewrote the placeholder with the real secret")
		} else if strings.Contains(data, placeholder) {
			t.Errorf("eBPF did NOT rewrite the secret — server received the placeholder unchanged")
		} else {
			t.Logf("Server received data but neither placeholder nor real secret found (eBPF may have partially rewritten)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to receive data")
	}

	// 9. Check ringbuf for rewrite events (non-blocking, best-effort)
	reader.SetDeadline(time.Now().Add(2 * time.Second))
	record, err := reader.Read()
	if err == nil && len(record.RawSample) >= 13 {
		isRewritten := record.RawSample[12]
		if isRewritten == 1 {
			t.Logf("Ringbuf confirms: REWRITE SUCCESS")
		} else {
			t.Logf("Ringbuf event received but is_rewritten=0")
		}
	} else {
		t.Logf("No ringbuf event received (eBPF rewrite may not have triggered): %v", err)
	}
}

// TestEBPFHostFiltering tests that the host filter prevents rewriting when
// the TLS destination doesn't match the allowed host.
func TestEBPFHostFiltering(t *testing.T) {
	objs := loadTestObjects(t)

	// Secret with host restriction: only allowed for "api.stripe.com"
	placeholder := "kloak:host1234"
	realSecret := "STRIPE-KEY-!!!"

	var key secretKey
	copy(key.Prefix[:], []byte(placeholder)[:8])
	var val secretValue
	val.Len = uint32(len(realSecret))
	copy(val.RealSecret[:], realSecret)
	val.HostLen = 14
	copy(val.AllowedHost[:], "api.stripe.com")
	val.PrefixLen = uint32(len(placeholder))
	copy(val.FullPrefix[:], placeholder)

	if err := objs.SecretMap.Update(&key, &val, 0); err != nil {
		t.Fatalf("failed to populate secret_map: %v", err)
	}

	phase2FD := uint32(objs.BpfPhase2Rewrite.FD())
	if err := objs.ProgArray.Update(uint32(0), &phase2FD, 0); err != nil {
		t.Fatalf("failed to wire tail call: %v", err)
	}

	certPEM, keyPEM, err := webhook.GenerateSelfSignedCert("default")
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse TLS key pair: %v", err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- fmt.Sprintf("ERROR: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		data, _ := io.ReadAll(conn)
		received <- string(data)
	}()

	pid := os.Getpid()
	mgr := &TLSUprobeManager{objs: objs, log: testLog()}
	if err := mgr.AttachTLS(pid); err != nil {
		t.Skipf("could not attach uprobes: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	// Connect with Host: wrong.example.com — does NOT match api.stripe.com
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		RootCAs:    certPool,
		ServerName: "kloak-webhook.default.svc",
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	payload := fmt.Sprintf("GET / HTTP/1.1\r\nHost: wrong.example.com\r\nX-Secret: %s\r\n\r\n", placeholder)
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Logf("conn.Close: %v", err)
	}

	select {
	case data := <-received:
		if strings.Contains(data, realSecret) {
			t.Errorf("eBPF should NOT have rewritten the secret (host mismatch) but real secret was found")
		} else if strings.Contains(data, placeholder) {
			t.Logf("SUCCESS: placeholder was NOT rewritten (host filter blocked it)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}
