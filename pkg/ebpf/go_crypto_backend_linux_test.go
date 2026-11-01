//go:build linux

package ebpf

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// goCryptoFixture makes TLS connections to itself and prints, for each, the
// cipher suite and its AEAD's Seal method (itab fun[3]) as an offset from the
// process's start_code: what the kprobe's type check computes. It then waits
// for stdin to close, so the test can read /proc/<pid> meanwhile.
const goCryptoFixture = `package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

func startCode() uintptr {
	b, _ := os.ReadFile("/proc/self/stat")
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	v, _ := strconv.ParseUint(f[23], 10, 64)
	return uintptr(v)
}

func main() {
	connToCipher, _ := strconv.Atoi(os.Args[1])
	aeadIfaceOff, _ := strconv.Atoi(os.Args[2])
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	for _, cfg := range []*tls.Config{
		{MinVersion: tls.VersionTLS13},
		{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}},
		{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}},
		{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}},
	} {
		cfg.InsecureSkipVerify = true
		c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil { // e.g. ChaCha20 under GODEBUG=fips140=on
			continue
		}
		cd := *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(c)) + uintptr(connToCipher)))
		itab := *(*uintptr)(unsafe.Pointer(cd + uintptr(aeadIfaceOff) - 8))
		seal := *(*uintptr)(unsafe.Pointer(itab + 24 + 3*8))
		fmt.Printf("%s %d\n", tls.CipherSuiteName(c.ConnectionState().CipherSuite), seal-startCode())
	}
	fmt.Println("READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
}
`

// TestGoAEADTypeCheckFixtures builds the fixture as plain Go, as a stripped
// PIE, with GOFIPS140=v1.0.0 and with GOEXPERIMENT=boringcrypto, runs it, and
// checks that goAEADSealOffsets predicts the Seal offset the kprobe sees for
// every AES-GCM connection of Go's own crypto, and for none of the others
// (ChaCha20, BoringCrypto's AES-GCM).
func TestGoAEADTypeCheckFixtures(t *testing.T) {
	if testing.Short() {
		t.Skip("builds Go binaries")
	}
	// The toolchain that built this test binary, on this machine: under
	// sudo (CI), PATH no longer has it.
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go") //nolint:staticcheck // SA1019: see above
	if _, err := os.Stat(goBin); err != nil {
		t.Skipf("no Go toolchain: %v", err)
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(goCryptoFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module fixture\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name    string
		env     []string
		flags   []string
		backend goCryptoBackend
	}{
		{"native", nil, nil, goCryptoNative},
		{"native-pie-stripped", nil, []string{"-buildmode=pie", "-ldflags=-s -w"}, goCryptoNative},
		{"fips140-v1.0.0", []string{"GOFIPS140=v1.0.0"}, nil, goCryptoNative},
		{"boringcrypto", []string{"GOEXPERIMENT=boringcrypto", "CGO_ENABLED=1"}, nil, goCryptoBoring},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.backend == goCryptoBoring {
				if _, err := exec.LookPath("gcc"); err != nil {
					t.Skip("boringcrypto needs cgo: no gcc")
				}
			}
			exe := filepath.Join(work, c.name)
			build := exec.Command(goBin, append(append([]string{"build", "-o", exe}, c.flags...), ".")...)
			build.Dir = src
			build.Env = append(append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS="), c.env...)
			asSudoUser(t, build, work)
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("go build: %v\n%s", err, out)
			}

			_, offsets, err := DetectGoTLSOffsets(exe)
			if err != nil {
				t.Fatalf("DetectGoTLSOffsets: %v", err)
			}
			info, err := inspectGoCrypto(exe)
			if err != nil {
				t.Fatalf("inspectGoCrypto: %v", err)
			}
			if info.Backend != c.backend {
				t.Fatalf("backend %v, want %v", info.Backend, c.backend)
			}

			run := exec.Command(exe, strconv.Itoa(int(offsets.ConnToCipher)), strconv.Itoa(int(offsets.AEADIfaceOff)))
			stdin, err := run.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := run.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			run.Stderr = os.Stderr
			if err := run.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stdin.Close(); _ = run.Wait() }()

			seen := map[string]uint32{}
			sc := bufio.NewScanner(stdout)
			for sc.Scan() && sc.Text() != "READY" {
				suite, off, ok := strings.Cut(sc.Text(), " ")
				v, err := strconv.ParseUint(off, 10, 32)
				if !ok || err != nil {
					t.Fatalf("fixture output %q", sc.Text())
				}
				seen[suite] = uint32(v)
			}
			if len(seen) == 0 {
				t.Fatal("fixture made no connection")
			}

			allowed, err := goAEADSealOffsets(run.Process.Pid, info)
			if err != nil {
				t.Fatalf("goAEADSealOffsets: %v (Seal methods %v)", err, info.AEADSeal)
			}
			for suite, off := range seen {
				aes := strings.Contains(suite, "AES")
				want := aes && c.backend == goCryptoNative
				if got := slices.Contains(allowed, off); got != want {
					t.Errorf("%s: Seal offset %#x allowed=%v, want %v (allowed %#x, Seal methods %v)",
						suite, off, got, want, allowed, fmtSeal(info.AEADSeal))
				}
			}
		})
	}
}

// asSudoUser runs cmd as the user who ran sudo, when the test runs under sudo
// (CI: go test -exec "sudo -E"), so a go build uses and fills that user's
// build cache without leaving root-owned entries in it. It hands dir, which
// holds everything cmd reads and writes, to that user.
func asSudoUser(t *testing.T, cmd *exec.Cmd, dir string) {
	t.Helper()
	if os.Getuid() != 0 {
		return
	}
	uid, uerr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gerr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uerr != nil || gerr != nil || uid == 0 {
		return
	}
	// t.TempDir's parent is 0700 root.
	if err := os.Chmod(filepath.Dir(dir), 0o711); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, uid, gid)
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
}

func fmtSeal(m map[string]uint64) string {
	var parts []string
	for name, addr := range m {
		parts = append(parts, fmt.Sprintf("%s=%#x", name, addr))
	}
	slices.Sort(parts)
	return strings.Join(parts, " ")
}
