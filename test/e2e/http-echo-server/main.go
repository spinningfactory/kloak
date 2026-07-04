// Command kloak-http-echo is a tiny in-cluster HTTPS server used by the
// eBPF e2e suite as a hermetic replacement for httpbin.org.
//
// Why it exists: the Go demo (examples/demo-go) used to send its secret
// headers to the public https://httpbin.org/headers and read the echoed
// headers back to observe the in-kernel rewrite. That made the nightly
// "Go Versions Nightly" e2e flaky — httpbin.org routinely rate-limits or
// times out under CI load, which surfaced as spurious "uprobe path failed
// to rewrite" failures even though the BPF path was healthy. This server
// runs inside the cluster so the test never touches the public internet.
//
// It intentionally mirrors two properties of the old httpbin.org target:
//
//  1. GET /headers returns {"headers": {...request headers...}} as JSON,
//     so the demo prints (and the test greps for) the value that actually
//     hit the wire after the rewrite.
//
//  2. It serves HTTP/2 over ALPN using Go's standard library server, whose
//     HPACK decoder is strict about EOS padding (RFC 7541 §5.2). That is
//     what preserves TestEBPFHttp2HpackOverPadding as a regression guard —
//     an over-padded header block is rejected by the h2 decoder exactly as
//     the AWS ALB fronting httpbin.org used to reject it.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// selfSignedCert mints an ephemeral ECDSA cert. Clients (the demo and the
// kubelet readiness probe) connect with verification disabled, so the SAN
// contents don't matter — only that a valid cert/key pair is presented so
// the TLS+ALPN handshake (and therefore HTTP/2 negotiation) completes.
func selfSignedCert() tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kloak-http-echo"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("x509 keypair: %v", err)
	}
	return cert
}

func main() {
	addr := ":8443"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}

	mux := http.NewServeMux()

	// Readiness endpoint for the pod's HTTPS readiness probe.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Everything else echoes the request headers back, httpbin-style, so the
	// caller can observe the post-rewrite wire value. Multi-valued headers are
	// joined with ", " to match httpbin's serialization.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string, len(r.Header))
		for k, v := range r.Header {
			headers[k] = strings.Join(v, ", ")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"headers": headers,
			"proto":   r.Proto,
		})
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{selfSignedCert()},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}

	// ListenAndServeTLS with empty cert/key paths uses TLSConfig.Certificates.
	// The stdlib server auto-configures HTTP/2 (adds "h2" to the ALPN list)
	// because TLSNextProto is nil — this is what gives us the strict HPACK
	// decoder the over-padding regression guard depends on.
	log.Printf("kloak-http-echo listening on %s (HTTP/1.1 + HTTP/2)", addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
