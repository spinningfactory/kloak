//go:build e2e_klor_rooted

package klor_e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// echoServer is an in-process HTTPS server used by the rewrite e2e
// tests. Listens on 127.0.0.1:<random>, terminates TLS with a fresh
// self-signed cert minted at startup, and echoes each request's body
// back in the response.
//
// Why in-process: avoids the external dependency on httpbin.org (which
// goes through systemd-resolved on most Linux hosts, breaking kloak's
// DNS chain) and lets the test assert the exact bytes the wire carried
// without having to parse a remote service's response format.
type echoServer struct {
	srv         *http.Server
	URL         string // https://127.0.0.1:<port>
	LastBody    atomic.Pointer[[]byte]
	requestSeen chan struct{}
}

// startEchoServer mints a fresh self-signed cert, binds to a random
// loopback port, and serves /. Caller defers stop(). Returns the
// server-side bodies seen via LastBody (set on each request) so tests
// can assert what actually landed on the wire.
func startEchoServer(t *testing.T) (srv *echoServer, stop func()) {
	t.Helper()

	cert := mintSelfSignedCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)

	e := &echoServer{
		URL:         fmt.Sprintf("https://127.0.0.1:%d", addr.Port),
		requestSeen: make(chan struct{}, 16),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		bcopy := make([]byte, len(body))
		copy(bcopy, body)
		e.LastBody.Store(&bcopy)
		select {
		case e.requestSeen <- struct{}{}:
		default:
		}
		// Echo the body back so the request side ALSO has a way to
		// confirm what landed (curl prints the response body to
		// stdout via the test wiring).
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	})
	e.srv = &http.Server{
		Handler:           mux,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		// ServeTLS with empty cert/key paths uses the certs already on
		// the TLSConfig — avoids writing keys to disk.
		_ = e.srv.ServeTLS(ln, "", "")
	}()

	stop = func() {
		_ = e.srv.Close()
		_ = ln.Close()
	}
	return e, stop
}

// waitForRequest blocks until one HTTPS request has been served, then
// returns the body the server saw. Used by tests to synchronize with
// the in-flight curl invocation without sleeps. Returns the empty
// slice on timeout so the caller can fail with a useful message.
func (e *echoServer) waitForRequest(timeout time.Duration) []byte {
	select {
	case <-e.requestSeen:
	case <-time.After(timeout):
		return nil
	}
	p := e.LastBody.Load()
	if p == nil {
		return nil
	}
	return *p
}

// mintSelfSignedCert generates a fresh P-256 ECDSA cert valid for
// 127.0.0.1, returned ready-to-load in a tls.Config. ECDSA over RSA
// because key generation is two orders of magnitude faster — every
// test invocation gets a unique cert so the server's identity can't
// be cached/reused across test runs.
func mintSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "kloak-test-echo"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}
