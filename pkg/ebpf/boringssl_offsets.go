package ebpf

import (
	"bytes"
	"debug/elf"
	"fmt"
	"strings"
)

// BoringSSLOffsets contains the struct offsets for walking an SSL* object to
// the AES-GCM hash key on a BoringSSL build. Unlike OpenSSL — whose provider
// GCM context persists the raw 16-byte hash subkey H (gcm128_context.H) —
// BoringSSL's GCM128_KEY stores only the precomputed, platform-specific GHASH
// powers table (Htable); the raw subkey ghash_key = AES_encrypt(0) is a local
// in CRYPTO_gcm128_init_aes_key that is discarded after the table is built.
//
// The chain is shorter than OpenSSL's (no OSSL_RECORD_LAYER indirection):
//
//	SSL* + SSLToS3        → SSL3_STATE*       (pointer deref)
//	     + S3ToAEAD       → SSLAEADContext*   (pointer deref; UniquePtr aead_write_ctx)
//	     + AEADToAESKey    → AES_KEY.rd_key   (direct read of the round-key schedule)
//
// AEADToAESKey collapses the embedded hops SSLAEADContext.ctx_ (EVP_AEAD_CTX,
// an embedded ScopedEVP_AEAD_CTX) → EVP_AEAD_CTX.state (embedded union) →
// aead_aes_gcm_ctx.key (GCM128_KEY) → gcm128_key_st.aes (AES_KEY). All hops
// after the first two are embedded structs, so AEADToAESKey is one additive
// offset.
//
// Why the AES_KEY and not the GHASH table: BoringSSL's GCM128_KEY persists
// only the precomputed, CPU-specific GHASH powers table (Htable) — never the
// raw 16-byte subkey H that kloak's tag recomputation needs. But it DOES keep
// the AES round-key schedule, and BoringSSL itself derives H exactly as
// H = AES_encrypt(0) over that schedule (see CRYPTO_gcm128_init_aes_key). So
// the BPF data plane reads AES_KEY.rd_key + rounds and recomputes
// H = AES_block(0) in-kernel (see the BoringSSL branch in
// pkg/ebpf/bpf/tls_uprobe.c). This is architecture- and GHASH-impl-independent,
// unlike recovering H from the Htable representation.
//
// AES_KEY layout: uint32_t rd_key[60] then uint32_t rounds, so the round count
// sits at AESKeyRoundsOff (240) bytes past rd_key.
//
// Offsets are discovered via pahole in tools/boringssl-offsets/ and committed
// to tools/boringssl-offsets/results/; TestBoringSSLOffsets_AgainstReferenceJSON
// asserts this table matches them.
type BoringSSLOffsets struct {
	SSLToS3      uint32 // SSL* → SSL3_STATE* (pointer deref)
	S3ToAEAD     uint32 // SSL3_STATE* → SSLAEADContext* (pointer deref, aead_write_ctx)
	AEADToAESKey uint32 // SSLAEADContext* → AES_KEY.rd_key (direct read)
	SSLToWBIO    uint32 // SSL* → wbio BIO* (socket fd recovery, same role as OpenSSL)
}

// AESKeyRoundsOff is the offset of AES_KEY.rounds past rd_key (rd_key is
// uint32_t[60] = 240 bytes). Constant across BoringSSL builds.
const AESKeyRoundsOff = 240

// boringsslOffsetTable maps a BoringSSL identity key to its struct offsets.
//
// BoringSSL is a rolling git repo and does not embed a resolvable semver in the
// shared library, so unlike OpenSSL there is no version string to key runtime
// detection off. The "default" row carries the offsets verified against the
// most-recent tracked release tag; the nightly discovery (keyed by release tag
// 0.YYYYMMDD.0 in tools/boringssl-offsets/results/) exists to DETECT DRIFT —
// if a new tag changes the layout, CI flags it and a tag-specific row is added.
// The struct navigation (s3, aead_write_ctx, embedded GCM key) has been stable
// across BoringSSL revisions.
var boringsslOffsetTable = map[string]BoringSSLOffsets{
	// Verified via pahole on aarch64 against release tag 0.20260616.0
	// (tools/boringssl-offsets/results/boringssl-0.20260616.0-arm64.json):
	//   ssl_st.s3 = 48, SSL3_STATE.aead_write_ctx = 272,
	//   SSLAEADContext.ctx_(8) + EVP_AEAD_CTX.state(8) + key(0) + gcm128_key.aes(272) = 288,
	//   ssl_st.wbio = 32.
	// The LP64 struct layout is architecture-independent (same on x86_64).
	"default": {SSLToS3: 48, S3ToAEAD: 272, AEADToAESKey: 288, SSLToWBIO: 32}, // verified against 0.20260526.0
}

// boringSSLMarkers are .rodata strings that uniquely identify a BoringSSL
// build (the version banner OpenSSL emits is absent; BoringSSL instead carries
// these compiled-in markers). Used to distinguish BoringSSL from OpenSSL when
// both expose an SSL_write symbol.
var boringSSLMarkers = []string{
	"openssl_is_boringssl",
	"BoringSSL",
	"vendor/boringssl",
}

// DetectBoringSSL reports whether the library/binary at libPath is BoringSSL
// and, if so, returns its struct offsets. The library is accessed via
// /proc/<pid>/root/<libPath> to reach into the container's overlay filesystem
// (libPath may instead be an absolute /proc path such as /proc/<pid>/exe).
//
// BoringSSL does not embed a resolvable version, so all builds map to the
// "default" offset row; the returned key is "default".
func DetectBoringSSL(pid int, libPath string) (key string, offsets BoringSSLOffsets, err error) {
	hostPath := libPath
	if !strings.HasPrefix(libPath, "/proc/") {
		hostPath = fmt.Sprintf("/proc/%d/root%s", pid, libPath)
	}

	f, err := elf.Open(hostPath)
	if err != nil {
		return "", BoringSSLOffsets{}, fmt.Errorf("opening ELF %s: %w", hostPath, err)
	}
	defer func() { _ = f.Close() }()

	if !isBoringSSL(f) {
		return "", BoringSSLOffsets{}, fmt.Errorf("%s is not BoringSSL", hostPath)
	}

	offsets, ok := boringsslOffsetTable["default"]
	if !ok || offsets.SSLToS3 == 0 {
		return "default", BoringSSLOffsets{}, fmt.Errorf("BoringSSL offsets not calibrated")
	}
	return "default", offsets, nil
}

// boringSSLSymbolMarkers are substrings that appear in BoringSSL symbol names
// but never in OpenSSL's. BoringSSL is C++ and namespaces most of its internals
// under `bssl::` (mangled as "N4bssl"...), exports BORINGSSL_-prefixed FIPS
// self-test entry points, and is the only one of the two with the EVP_AEAD API.
// These live in the symbol tables (.dynsym/.symtab → .dynstr/.strtab), NOT in
// .rodata — which is why a .rodata-only scan misses them on shared libraries.
var boringSSLSymbolMarkers = []string{"BORINGSSL_", "N4bssl", "EVP_AEAD_CTX_seal"}

// isBoringSSL reports whether an ELF is BoringSSL. It checks the symbol tables
// for BoringSSL-only symbol names (the reliable signal on stripped-of-rodata
// shared libs) and falls back to scanning .rodata/.data for the textual markers
// (which the packaged claude binary carries).
func isBoringSSL(f *elf.File) bool {
	for _, syms := range [][]elf.Symbol{symbolsOf(f), dynSymbolsOf(f)} {
		for i := range syms {
			name := syms[i].Name
			for _, m := range boringSSLSymbolMarkers {
				if strings.Contains(name, m) {
					return true
				}
			}
		}
	}
	for _, name := range []string{".rodata", ".data"} {
		sec := f.Section(name)
		if sec == nil {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		for _, m := range boringSSLMarkers {
			if bytes.Contains(data, []byte(m)) {
				return true
			}
		}
	}
	return false
}

func symbolsOf(f *elf.File) []elf.Symbol {
	s, err := f.Symbols()
	if err != nil {
		return nil
	}
	return s
}

func dynSymbolsOf(f *elf.File) []elf.Symbol {
	s, err := f.DynamicSymbols()
	if err != nil {
		return nil
	}
	return s
}
