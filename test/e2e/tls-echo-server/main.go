// tls-echo-server: a simple HTTPS server that echoes back request headers.
// Used by kloak e2e tests to verify secret rewriting across cipher suites.
//
// The server generates a self-signed certificate at startup and listens on :8443.
// It supports configuring allowed cipher suites and TLS versions via environment variables.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	// Generate self-signed certificate.
	cert, err := generateSelfSignedCert()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate cert: %v\n", err)
		os.Exit(1)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Configure TLS version from env.
	if v := os.Getenv("TLS_MIN_VERSION"); v != "" {
		switch v {
		case "1.2":
			tlsCfg.MinVersion = tls.VersionTLS12
		case "1.3":
			tlsCfg.MinVersion = tls.VersionTLS13
		}
	}
	if v := os.Getenv("TLS_MAX_VERSION"); v != "" {
		switch v {
		case "1.2":
			tlsCfg.MaxVersion = tls.VersionTLS12
		case "1.3":
			tlsCfg.MaxVersion = tls.VersionTLS13
		}
	}

	// Configure cipher suites from env (comma-separated names).
	if cs := os.Getenv("TLS_CIPHER_SUITES"); cs != "" {
		names := strings.Split(cs, ",")
		var suites []uint16
		for _, name := range names {
			name = strings.TrimSpace(name)
			for _, s := range tls.CipherSuites() {
				if s.Name == name {
					suites = append(suites, s.ID)
					break
				}
			}
			// Also check insecure suites for testing.
			for _, s := range tls.InsecureCipherSuites() {
				if s.Name == name {
					suites = append(suites, s.ID)
					break
				}
			}
		}
		if len(suites) > 0 {
			tlsCfg.CipherSuites = suites
			fmt.Printf("Configured cipher suites: %v\n", names)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		// Echo back all request headers as JSON.
		resp := map[string]interface{}{
			"headers":     r.Header,
			"tls_version": tlsVersionName(r.TLS.Version),
			"cipher":      tls.CipherSuiteName(r.TLS.CipherSuite),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	fmt.Println("TLS echo server listening on :8443")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tls-echo-server"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"tls-echo-server", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}
