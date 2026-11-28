// Command kloak-lossy-tls is the e2e suite's tool for lossy and segmented
// network scenarios (TestEBPFLossyNetwork, kloak#383): a TLS echo server,
// and a client that sends a placeholder many times and counts what came
// back.
//
//	kloak-lossy-tls server
//	kloak-lossy-tls client
//
// The protocol is a 4-byte big-endian length and that many bytes, echoed
// back the same way, any number of times on a connection. A message is
// FILLER_BEFORE filler bytes, the allowed placeholder, a newline, the
// blocked placeholder, a newline, FILLER_AFTER filler bytes: the filler
// before a placeholder pushes it into a TLS record's later segments, or
// into Go's second record on a new connection (dynamic record sizing).
// AFTER_SPREAD varies the filler after it from request to request over that
// many bytes, so that the record's end, and its tag, fall at every offset
// of a segment.
//
// The client only ever holds the placeholders (kloak's shadow secrets). It
// tells the outcome of each request from SHA-256 digests of the real
// values (REAL_SHA256, BLOCKED_REAL_SHA256), so the real values are never
// in its pod: correct (the allowed placeholder came back as the real value,
// the blocked one as itself), shadow (came back unrewritten), wrong
// (anything else: the bytes authenticated, but are not what was sent or
// its rewrite), blocked_leak (the blocked secret's real value came back),
// or the error that ended the request (bad_record_mac: the server's
// alert, reset, timeout, other_error). It prints one RESULT line of JSON.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxMessage = 1 << 20

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: kloak-lossy-tls server|client")
	}
	switch os.Args[1] {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		log.Fatalf("unknown mode %q", os.Args[1])
	}
}

func selfSignedCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func runServer() {
	ln, err := tls.Listen("tcp", ":8443", &tls.Config{Certificates: []tls.Certificate{selfSignedCert()}})
	if err != nil {
		log.Fatal(err)
	}
	log.Print("listening on :8443")
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer func() { _ = c.Close() }()
			for {
				msg, err := readMessage(c, 30*time.Second)
				if err != nil {
					// A probe's bare TCP connect, or the client closing.
					if !errors.Is(err, io.EOF) {
						log.Printf("%s: %v", c.RemoteAddr(), err)
					}
					return
				}
				if err := writeMessage(c, msg); err != nil {
					log.Printf("%s: %v", c.RemoteAddr(), err)
					return
				}
			}
		}()
	}
}

func readMessage(c net.Conn, timeout time.Duration) ([]byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	var n [4]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return nil, err
	}
	l := binary.BigEndian.Uint32(n[:])
	if l > maxMessage {
		return nil, fmt.Errorf("message of %d bytes", l)
	}
	msg := make([]byte, l)
	if _, err := io.ReadFull(c, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeMessage(c net.Conn, msg []byte) error {
	// One Write, so that the TLS library cuts the message into records as
	// it would an application's request.
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(msg)))
	_, err := c.Write(append(buf, msg...))
	return err
}

// Result is the client's RESULT line.
type Result struct {
	Requests     int            `json:"requests"`
	Counts       map[string]int `json:"counts"`
	Errors       []string       `json:"errors,omitempty"` // the first distinct error messages
	WarmupMillis int64          `json:"warmup_ms"`
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	v, err := strconv.Atoi(env(name, strconv.Itoa(def)))
	if err != nil {
		log.Fatalf("%s: %v", name, err)
	}
	return v
}

func readSecret(name string) []byte {
	b, err := os.ReadFile(env(name, ""))
	if err != nil {
		log.Fatalf("%s: %v", name, err)
	}
	return bytes.TrimSpace(b)
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// filler returns n bytes of letters that hold no placeholder.
func filler(n int) []byte {
	return bytes.Repeat([]byte("abcdefghijklmnopqrstuvwxyz"), n/26+1)[:n]
}

type tlsClient struct {
	target, serverName  string
	allowed, blocked    []byte
	realSum, blockedSum string
	before, after       int
	spread              int
	cfg                 *tls.Config
	timeout             time.Duration
	conn                net.Conn
}

// waitMTU waits for the pod's interface to have the MTU the test sets on it
// (after turning segmentation offload off), so that every connection is
// opened with the MSS the scenario wants.
func waitMTU(mtu string) {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		b, _ := os.ReadFile("/sys/class/net/eth0/mtu")
		if strings.TrimSpace(string(b)) == mtu {
			log.Printf("eth0 mtu is %s", mtu)
			return
		}
		if time.Now().After(deadline) {
			log.Fatalf("eth0 mtu is %q, not %s", strings.TrimSpace(string(b)), mtu)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func runClient() {
	if mtu := os.Getenv("WAIT_MTU"); mtu != "" {
		waitMTU(mtu)
	}
	c := &tlsClient{
		target:     env("TARGET", ""),
		serverName: env("SERVER_NAME", ""),
		allowed:    readSecret("SECRET_FILE"),
		blocked:    readSecret("BLOCKED_FILE"),
		realSum:    env("REAL_SHA256", ""),
		blockedSum: env("BLOCKED_REAL_SHA256", ""),
		before:     envInt("FILLER_BEFORE", 0),
		after:      envInt("FILLER_AFTER", 0),
		spread:     envInt("AFTER_SPREAD", 0),
		timeout:    time.Duration(envInt("TIMEOUT_MS", 3000)) * time.Millisecond,
	}
	c.cfg = &tls.Config{
		ServerName:                  c.serverName,
		InsecureSkipVerify:          true, // the server's certificate is self-signed
		DynamicRecordSizingDisabled: env("DYNAMIC_RECORDS", "1") == "0",
	}
	if env("TLS_MAX", "1.3") == "1.2" {
		c.cfg.MaxVersion = tls.VersionTLS12
	}
	requests := envInt("REQUESTS", 100)
	fresh := env("FRESH_CONN", "0") == "1"

	// Warm up until one small request is rewritten: kloak attaches to the
	// process when it starts (or shortly after, without NRI). Not counted.
	start := time.Now()
	for {
		if out, _ := c.request(true, 0, 0); out == "correct" {
			break
		}
		if time.Since(start) > 90*time.Second {
			log.Fatal("no request was rewritten in 90 s of warm-up")
		}
		time.Sleep(200 * time.Millisecond)
	}
	c.close()

	res := Result{Requests: requests, Counts: map[string]int{}, WarmupMillis: time.Since(start).Milliseconds()}
	seen := map[string]bool{}
	for i := 0; i < requests; i++ {
		after := c.after
		if c.spread > 0 {
			after += i * 7919 % c.spread // a stride prime to any MSS
		}
		out, err := c.request(fresh, c.before, after)
		res.Counts[out]++
		if err != nil && !seen[err.Error()] && len(res.Errors) < 5 {
			seen[err.Error()] = true
			res.Errors = append(res.Errors, err.Error())
		}
	}
	c.close()
	b, _ := json.Marshal(res)
	fmt.Printf("RESULT %s\n", b)
}

func (c *tlsClient) close() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// request sends one message and classifies what came back.
func (c *tlsClient) request(fresh bool, before, after int) (string, error) {
	if fresh {
		c.close()
	}
	if c.conn == nil {
		d := &net.Dialer{Timeout: c.timeout}
		conn, err := tls.DialWithDialer(d, "tcp", c.target, c.cfg)
		if err != nil {
			return classify(err), err
		}
		c.conn = conn
	}
	msg := append(filler(before), c.allowed...)
	msg = append(append(msg, '\n'), c.blocked...)
	msg = append(append(msg, '\n'), filler(after)...)
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if err := writeMessage(c.conn, msg); err != nil {
		c.close()
		return classify(err), err
	}
	echo, err := readMessage(c.conn, c.timeout)
	if err != nil {
		c.close()
		return classify(err), err
	}
	return c.judge(msg, echo, before), nil
}

func (c *tlsClient) judge(sent, echo []byte, before int) string {
	a, b := before, before+len(c.allowed)+1
	if len(echo) != len(sent) {
		return "wrong"
	}
	allowed, blocked := echo[a:a+len(c.allowed)], echo[b:b+len(c.blocked)]
	if c.blockedSum != "" && digest(blocked) == c.blockedSum {
		return "blocked_leak"
	}
	// Everything but the allowed placeholder comes back as sent.
	if !bytes.Equal(echo[:a], sent[:a]) || !bytes.Equal(echo[a+len(c.allowed):], sent[a+len(c.allowed):]) {
		return "wrong"
	}
	switch {
	case digest(allowed) == c.realSum:
		return "correct"
	case bytes.Equal(allowed, c.allowed):
		return "shadow"
	default:
		return "wrong"
	}
}

func classify(err error) string {
	var ne net.Error
	switch {
	case strings.Contains(err.Error(), "bad record MAC"):
		return "bad_record_mac"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.EPIPE):
		return "reset"
	default:
		return "other_error"
	}
}
