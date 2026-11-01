package ebpf

import (
	"debug/buildinfo"
	"encoding/binary"
	"runtime/debug"
	"slices"
	"testing"
)

func TestGoNativeAEADSealPattern(t *testing.T) {
	allowed := []string{
		"crypto/aes.(*gcmAsm).Seal",                                           // Go 1.20–1.23
		"crypto/internal/fips140/aes/gcm.(*GCM).Seal",                         // Go 1.24+
		"crypto/internal/fips140/aes/gcm.(*GCMForTLS12).Seal",                 // Go 1.24, 1.25
		"crypto/internal/fips140/aes/gcm.(*GCMForTLS13).Seal",                 // Go 1.24, 1.25
		"crypto/internal/fips140/aes/gcm.(*GCMWithCounterNonce).Seal",         // Go 1.26+
		"crypto/internal/fips140/aes/gcm.(*GCMWithXORCounterNonce).Seal",      // Go 1.26+
		"crypto/internal/fips140/v1.0.0-c2097c7c/aes/gcm.(*GCMForTLS12).Seal", // GOFIPS140=v1.0.0
		"crypto/internal/fips140/v1.26.0/aes/gcm.(*GCMWithCounterNonce).Seal",
	}
	refused := []string{
		"crypto/cipher.(*gcm).Seal",         // Go ≤1.23 software fallback: other layout
		"crypto/cipher.(*gcmFallback).Seal", // Go 1.24+ non-standard nonce/tag sizes
		"crypto/internal/boring.(*aesGCM).Seal",
		"vendor/golang.org/x/crypto/chacha20poly1305.(*chacha20poly1305).Seal",
		"vendor/github.com/golang-fips/openssl/v2.(*cipherGCM).Seal",
		"crypto/internal/fips140/aes/gcm.(*GCMForSSH).Seal",
		"crypto/internal/fips140/aes/gcm.(*GCM).Open",
		"crypto/internal/fips140/aes/gcm.(*GCM).Seal-fm",
		"example.com/crypto/internal/fips140/aes/gcm.(*GCM).Seal",
	}
	for _, name := range allowed {
		if !goNativeAEADSeal.MatchString(name) {
			t.Errorf("%s not allowed", name)
		}
	}
	for _, name := range refused {
		if goNativeAEADSeal.MatchString(name) {
			t.Errorf("%s allowed", name)
		}
	}
}

func TestGoCryptoBackendFromBuildInfo(t *testing.T) {
	for _, c := range []struct {
		settings []debug.BuildSetting
		want     goCryptoBackend
	}{
		{nil, goCryptoNative},
		{[]debug.BuildSetting{{Key: "GOFIPS140", Value: "v1.0.0-c2097c7c"}}, goCryptoNative},
		{[]debug.BuildSetting{{Key: "GOEXPERIMENT", Value: "boringcrypto"}}, goCryptoBoring},
		{[]debug.BuildSetting{{Key: "GOEXPERIMENT", Value: "arenas,boringcrypto"}}, goCryptoBoring},
		{[]debug.BuildSetting{{Key: "GOEXPERIMENT", Value: "systemcrypto"}}, goCryptoOpenSSL},
		{[]debug.BuildSetting{{Key: "GOEXPERIMENT", Value: "opensslcrypto"}}, goCryptoOpenSSL},
		{[]debug.BuildSetting{{Key: "GOEXPERIMENT", Value: "nosystemcrypto"}}, goCryptoNative},
	} {
		if got := goCryptoBackendFromBuildInfo(&buildinfo.BuildInfo{Settings: c.settings}); got != c.want {
			t.Errorf("%v: got %v, want %v", c.settings, got, c.want)
		}
	}
}

func TestParseStatStartCode(t *testing.T) {
	// Fields 3..25, then startcode (26) = 4198400; the command holds ") ".
	stat := "1234 (we) ird) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 5 0 300 1000000 200 " +
		"18446744073709551615 4198400 4300000 140736000000000 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0"
	got, err := parseStatStartCode(stat)
	if err != nil || got != 4198400 {
		t.Fatalf("got %d, %v; want 4198400", got, err)
	}
	hidden := "1 (x) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 1 1 18446744073709551615 0 0 0"
	if _, err := parseStatStartCode(hidden); err == nil {
		t.Error("startcode 0 (hidden) accepted")
	}
	if _, err := parseStatStartCode("1 (x) S 1"); err == nil {
		t.Error("short stat accepted")
	}
}

func TestParseAuxvEntry(t *testing.T) {
	auxv := func(pairs ...uint64) []byte {
		b := make([]byte, 8*len(pairs))
		for i, v := range pairs {
			binary.NativeEndian.PutUint64(b[8*i:], v)
		}
		return b
	}
	got, err := parseAuxvEntry(auxv(6, 4096, atEntry, 0x55550000a000, 0, 0))
	if err != nil || got != 0x55550000a000 {
		t.Fatalf("got %#x, %v", got, err)
	}
	// Nothing after AT_NULL counts.
	if _, err := parseAuxvEntry(auxv(6, 4096, 0, 0, atEntry, 1)); err == nil {
		t.Error("AT_ENTRY after AT_NULL accepted")
	}
}

func TestSetAEADSealOffsets(t *testing.T) {
	var o GoTLSOffsets
	o.setAEADSealOffsets([]uint32{0x10, 0x20})
	if o.AEADSealCount != 2 || !slices.Equal(o.AEADSealOff[:3], []uint32{0x10, 0x20, 0}) {
		t.Fatalf("got %+v", o)
	}
	o.setAEADSealOffsets(nil)
	if o.AEADSealCount != 0 || o.AEADSealOff != [goAEADSealMax]uint32{} {
		t.Fatalf("not cleared: %+v", o)
	}
}

func TestGoAEADSealOffsetsNoSeal(t *testing.T) {
	if _, err := goAEADSealOffsets(1, goCryptoInfo{AEADSeal: map[string]uint64{}}); err == nil {
		t.Error("no Seal method: want an error")
	}
}
