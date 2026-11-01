package ebpf

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// goAEADSealMax mirrors GO_AEAD_SEAL_MAX in tls_uprobe.c.
const goAEADSealMax = 8

// goCryptoBackend is what implements AES-GCM for crypto/tls in a Go binary.
// Only goCryptoNative keeps the H×2 table the kprobe reads (go_tls_offsets.go);
// see spinningfactory/kloak#365 for the others.
type goCryptoBackend int

const (
	// goCryptoNative is Go's own crypto, including Go 1.24+'s FIPS 140-3
	// module (GOFIPS140, GODEBUG=fips140=on|only).
	goCryptoNative goCryptoBackend = iota
	// goCryptoBoring is GOEXPERIMENT=boringcrypto: AES-GCM runs in an
	// embedded BoringSSL (crypto/internal/boring.aesGCM).
	goCryptoBoring
	// goCryptoOpenSSL is a toolchain that hands crypto to OpenSSL through
	// golang-fips/openssl: Microsoft's Go (systemcrypto) and Red Hat's Go
	// toolset. Red Hat's picks OpenSSL at run time (FIPS mode) and Go's own
	// crypto otherwise, so a binary can use either.
	goCryptoOpenSSL
)

func (b goCryptoBackend) String() string {
	switch b {
	case goCryptoNative:
		return "native"
	case goCryptoBoring:
		return "boringcrypto"
	case goCryptoOpenSSL:
		return "openssl"
	}
	return "unknown"
}

// goNativeAEADSeal matches the Seal method of each of Go's own AES-GCM types
// that crypto/tls puts behind its cipher.AEAD, the only types whose H×2 table
// go_tls_offsets.go knows how to read:
//
//	Go 1.20–1.23: crypto/aes.(*gcmAsm), the AES-NI / ARMv8 path. The
//	              software fallback crypto/cipher.(*gcm) is left out on
//	              purpose: its productTable sits 8 bytes further.
//	Go 1.24+:     crypto/internal/fips140/aes/gcm.(*GCMForTLS12) and
//	              (*GCMForTLS13) (1.24, 1.25), (*GCMWithCounterNonce) and
//	              (*GCMWithXORCounterNonce) (1.26+), and (*GCM), which they
//	              embed at offset 0. With GOFIPS140 set to a frozen module the
//	              package path carries its version
//	              (crypto/internal/fips140/v1.0.0-c2097c7c/aes/gcm).
//
// Go 1.24's generic GCM (no AES hardware) is one of these types but never
// fills the table; the kprobe refuses its all-zero H.
var goNativeAEADSeal = regexp.MustCompile(
	`^crypto/(aes\.\(\*gcmAsm\)|internal/fips140(/v[^/]+)?/aes/gcm\.\(\*(GCM|GCMForTLS12|GCMForTLS13|GCMWithCounterNonce|GCMWithXORCounterNonce)\))\.Seal$`)

const (
	// goBoringAEADSeal exists only in GOEXPERIMENT=boringcrypto builds
	// (crypto/internal/boring/aes.go is behind the boringcrypto build tag).
	goBoringAEADSeal = "crypto/internal/boring.(*aesGCM).Seal"
	// goOpenSSLPackage is in the function names of OpenSSL-backed toolchains:
	// github.com/golang-fips/openssl (v2, Microsoft and Red Hat) and
	// github.com/golang-fips/openssl-fips (older Red Hat releases).
	goOpenSSLPackage = "github.com/golang-fips/openssl"
)

// goCryptoInfo is what kloak reads from a Go binary about its TLS crypto.
type goCryptoInfo struct {
	Backend goCryptoBackend
	// AEADSeal maps the name of each allowed AEAD Seal method (see
	// goNativeAEADSeal) to its link-time address.
	AEADSeal map[string]uint64
	// Entry is the ELF entry point, used to find the process's PIE load bias.
	Entry uint64
}

// inspectGoCrypto reads a Go binary's crypto backend and the addresses of its
// AES-GCM Seal methods. It only needs the pclntab, which -s -w keeps, so it
// works on stripped binaries, PIE or not. On error, Backend still reports what
// the build info says.
func inspectGoCrypto(exePath string) (goCryptoInfo, error) {
	info := goCryptoInfo{Backend: goCryptoNative, AEADSeal: map[string]uint64{}}
	if bi, err := buildinfo.ReadFile(exePath); err == nil {
		info.Backend = goCryptoBackendFromBuildInfo(bi)
	}

	f, err := elf.Open(exePath)
	if err != nil {
		return info, fmt.Errorf("opening ELF %s: %w", exePath, err)
	}
	defer func() { _ = f.Close() }()
	info.Entry = f.Entry

	tab, err := goSymTable(f)
	if err != nil {
		return info, err
	}
	for i := range tab.Funcs {
		fn := &tab.Funcs[i]
		switch {
		case goNativeAEADSeal.MatchString(fn.Name):
			info.AEADSeal[fn.Name] = fn.Entry
		case fn.Name == goBoringAEADSeal:
			info.Backend = goCryptoBoring
		case info.Backend == goCryptoNative && strings.Contains(fn.Name, goOpenSSLPackage):
			info.Backend = goCryptoOpenSSL
		}
	}
	return info, nil
}

// goCryptoBackendFromBuildInfo reads the backend from the GOEXPERIMENT build
// setting. Toolchains that enable a backend by default may not record it, so
// inspectGoCrypto also looks for the backend's functions.
func goCryptoBackendFromBuildInfo(bi *buildinfo.BuildInfo) goCryptoBackend {
	for _, s := range bi.Settings {
		if s.Key != "GOEXPERIMENT" {
			continue
		}
		for _, exp := range strings.Split(s.Value, ",") {
			switch exp {
			case "boringcrypto":
				return goCryptoBoring
			case "systemcrypto", "opensslcrypto":
				return goCryptoOpenSSL
			}
		}
	}
	return goCryptoNative
}

// goSymTable parses a Go binary's pclntab. PIE binaries keep it in
// .data.rel.ro.gopclntab.
func goSymTable(f *elf.File) (*gosym.Table, error) {
	sec := f.Section(".gopclntab")
	if sec == nil {
		sec = f.Section(".data.rel.ro.gopclntab")
	}
	if sec == nil {
		return nil, errors.New("no pclntab section")
	}
	text := f.Section(".text")
	if text == nil {
		return nil, errors.New("no .text section")
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("reading pclntab: %w", err)
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		return nil, fmt.Errorf("parsing pclntab: %w", err)
	}
	return tab, nil
}

// goAEADSealOffsets returns each allowed Seal method of info as the offset
// the kprobe compares against: its address minus the process's
// mm->start_code. Both move by the PIE load bias, so the offset is the same
// in every process running the binary, which is what the per-binary
// go_tls_offset_config entry needs.
func goAEADSealOffsets(pid int, info goCryptoInfo) ([]uint32, error) {
	if len(info.AEADSeal) == 0 {
		return nil, errors.New("no Go AES-GCM Seal method in the pclntab")
	}
	base, err := goProcessCodeBase(pid, info.Entry)
	if err != nil {
		return nil, err
	}
	offs := make([]uint32, 0, len(info.AEADSeal))
	for name, addr := range info.AEADSeal {
		if addr < base || addr-base > 0xFFFFFFFF {
			return nil, fmt.Errorf("%s at %#x is out of range of the code base %#x", name, addr, base)
		}
		offs = append(offs, uint32(addr-base))
	}
	slices.Sort(offs)
	if len(offs) > goAEADSealMax {
		return nil, fmt.Errorf("%d Go AES-GCM Seal methods, at most %d supported", len(offs), goAEADSealMax)
	}
	return offs, nil
}

// setAEADSealOffsets enables the kprobe's AEAD type check with offs (from
// goAEADSealOffsets); nil disables it.
func (o *GoTLSOffsets) setAEADSealOffsets(offs []uint32) {
	o.AEADSealOff = [goAEADSealMax]uint32{}
	o.AEADSealCount = uint32(copy(o.AEADSealOff[:], offs))
}

// goProcessCodeBase returns the link-time address that process pid's
// mm->start_code corresponds to: start_code minus the load bias, which is
// AT_ENTRY minus the ELF entry point (0 for a non-PIE binary). Reading the
// kernel's own start_code avoids depending on how it picks it from the
// program headers.
func goProcessCodeBase(pid int, elfEntry uint64) (uint64, error) {
	startCode, err := procStartCode(pid)
	if err != nil {
		return 0, err
	}
	atEntry, err := procAuxvEntry(pid)
	if err != nil {
		return 0, err
	}
	bias := atEntry - elfEntry
	if startCode < bias {
		return 0, fmt.Errorf("start_code %#x below the load bias %#x", startCode, bias)
	}
	return startCode - bias, nil
}

// procStartCode reads startcode, field 26 of /proc/<pid>/stat. The kernel
// reports 0 to a reader without ptrace access to the process.
func procStartCode(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	return parseStatStartCode(string(data))
}

func parseStatStartCode(stat string) (uint64, error) {
	// The command (field 2) is parenthesized and may hold spaces and ')'.
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, errors.New("malformed /proc/<pid>/stat")
	}
	fields := strings.Fields(stat[end+1:])
	const startCodeField = 26 - 3 // fields after the command start at 3
	if len(fields) <= startCodeField {
		return 0, errors.New("short /proc/<pid>/stat")
	}
	v, err := strconv.ParseUint(fields[startCodeField], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("startcode: %w", err)
	}
	if v == 0 {
		return 0, errors.New("startcode hidden (no ptrace access to the process)")
	}
	return v, nil
}

// atEntry is the auxiliary vector's program entry point (AT_ENTRY).
const atEntry = 9

// procAuxvEntry reads AT_ENTRY from /proc/<pid>/auxv.
func procAuxvEntry(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/auxv", pid))
	if err != nil {
		return 0, err
	}
	return parseAuxvEntry(data)
}

// parseAuxvEntry finds AT_ENTRY in a 64-bit auxiliary vector (pairs of
// native-endian uint64; kloak runs on its targets' architecture).
func parseAuxvEntry(auxv []byte) (uint64, error) {
	for i := 0; i+16 <= len(auxv); i += 16 {
		key := binary.NativeEndian.Uint64(auxv[i:])
		if key == 0 { // AT_NULL
			break
		}
		if key == atEntry {
			return binary.NativeEndian.Uint64(auxv[i+8:]), nil
		}
	}
	return 0, errors.New("no AT_ENTRY in auxv")
}
