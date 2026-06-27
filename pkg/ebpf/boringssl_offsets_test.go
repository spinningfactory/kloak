package ebpf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// boringSSLReferenceJSON mirrors the kloak_config section emitted by
// tools/boringssl-offsets/extract_offsets.sh for a single (tag, arch) cell.
// Pointer types distinguish null (extraction failed) from 0 (valid zero offset).
type boringSSLReferenceJSON struct {
	Version     string `json:"version"`
	Arch        string `json:"arch"`
	KloakConfig struct {
		SSLToS3      *uint32 `json:"SSLToS3"`
		S3ToAEAD     *uint32 `json:"S3ToAEAD"`
		AEADToAESKey *uint32 `json:"AEADToAESKey"`
		SSLToWBIO    *uint32 `json:"SSLToWBIO"`
	} `json:"kloak_config"`
}

// parseBoringSSLFixtureFilename extracts (tag, arch) from a
// boringssl-<tag>-<arch>.json filename. The tag itself contains dots
// (0.YYYYMMDD.0) but no dashes, so splitting on the last dash is safe.
func parseBoringSSLFixtureFilename(base string) (tag, arch string, ok bool) {
	stripped := strings.TrimSuffix(base, ".json")
	stripped = strings.TrimPrefix(stripped, "boringssl-")
	idx := strings.LastIndex(stripped, "-")
	if idx < 0 {
		return "", "", false
	}
	return stripped[:idx], stripped[idx+1:], true
}

// TestBoringSSLOffsets_AgainstReferenceJSON is the primary CI check for
// BoringSSL offsets: every committed reference JSON in
// tools/boringssl-offsets/results/ must agree with the single "default" row in
// boringsslOffsetTable. Because BoringSSL embeds no resolvable version, kloak
// keys every build to "default"; this test therefore also enforces that the
// struct layout is stable across all tracked release tags — if a new tag
// drifts, the auto-PR that commits its JSON turns this test red, which is the
// intended drift signal.
//
// Runs as a plain Go test — no Docker, no network. Self-skips when no results
// are committed yet (e.g. before the first nightly discovery run).
func TestBoringSSLOffsets_AgainstReferenceJSON(t *testing.T) {
	pattern := filepath.Join("..", "..", "tools", "boringssl-offsets", "results", "boringssl-*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %q: %v", pattern, err)
	}
	if len(paths) == 0 {
		t.Skipf("no reference JSONs at %s — run the boringssl-offsets workflow and commit results", pattern)
	}

	def, ok := boringsslOffsetTable["default"]
	if !ok {
		t.Fatalf("boringsslOffsetTable has no \"default\" row")
	}

	for _, p := range paths {
		base := filepath.Base(p)
		tag, arch, ok := parseBoringSSLFixtureFilename(base)
		if !ok {
			t.Errorf("unparseable result filename: %s", base)
			continue
		}
		t.Run(fmt.Sprintf("%s-%s", tag, arch), func(t *testing.T) {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			var ref boringSSLReferenceJSON
			if err := json.Unmarshal(data, &ref); err != nil {
				t.Fatalf("parse %s: %v", p, err)
			}
			if ref.KloakConfig.SSLToS3 == nil || ref.KloakConfig.S3ToAEAD == nil ||
				ref.KloakConfig.AEADToAESKey == nil || ref.KloakConfig.SSLToWBIO == nil {
				t.Fatalf("one or more offsets are null/missing in %s — re-run discovery", base)
			}
			if def.SSLToS3 != *ref.KloakConfig.SSLToS3 {
				t.Errorf("SSLToS3 mismatch: table=%d ref=%d", def.SSLToS3, *ref.KloakConfig.SSLToS3)
			}
			if def.S3ToAEAD != *ref.KloakConfig.S3ToAEAD {
				t.Errorf("S3ToAEAD mismatch: table=%d ref=%d", def.S3ToAEAD, *ref.KloakConfig.S3ToAEAD)
			}
			if def.AEADToAESKey != *ref.KloakConfig.AEADToAESKey {
				t.Errorf("AEADToAESKey mismatch: table=%d ref=%d", def.AEADToAESKey, *ref.KloakConfig.AEADToAESKey)
			}
			if def.SSLToWBIO != *ref.KloakConfig.SSLToWBIO {
				t.Errorf("SSLToWBIO mismatch: table=%d ref=%d", def.SSLToWBIO, *ref.KloakConfig.SSLToWBIO)
			}
		})
	}
}

// TestBoringSSLOffsetTable_Sane guards against an empty/zeroed default row,
// which would make DetectBoringSSL silently return uncalibrated offsets.
func TestBoringSSLOffsetTable_Sane(t *testing.T) {
	def, ok := boringsslOffsetTable["default"]
	if !ok {
		t.Fatalf("boringsslOffsetTable missing \"default\" row")
	}
	if def.SSLToS3 == 0 || def.S3ToAEAD == 0 || def.AEADToAESKey == 0 || def.SSLToWBIO == 0 {
		t.Errorf("default row has a zero offset: %+v", def)
	}
}

func TestIsBoringSSLMarkers(t *testing.T) {
	// bytesContains is the substring scan isBoringSSL relies on.
	if !bytesContains([]byte("xx\x00openssl_is_boringssl\x00yy"), []byte("openssl_is_boringssl")) {
		t.Errorf("expected marker to be found")
	}
	if bytesContains([]byte("OpenSSL 3.2.1"), []byte("openssl_is_boringssl")) {
		t.Errorf("did not expect marker in OpenSSL banner")
	}
}
