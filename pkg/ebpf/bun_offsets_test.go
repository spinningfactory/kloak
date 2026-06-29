package ebpf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bunReferenceJSON mirrors the shape emitted by tools/bun-offsets/discover.sh.
type bunReferenceJSON struct {
	Version        string `json:"version"`
	Arch           string `json:"arch"`
	SSLWriteOffset uint64 `json:"ssl_write_offset"`
	BoringSSL      struct {
		SSLToS3      *uint32 `json:"SSLToS3"`
		S3ToAEAD     *uint32 `json:"S3ToAEAD"`
		AEADToAESKey *uint32 `json:"AEADToAESKey"`
		SSLToWBIO    *uint32 `json:"SSLToWBIO"`
	} `json:"boringssl"`
}

// parseBunFixtureFilename extracts (version, arch) from bun-<version>-<arch>.json.
// The version contains dots but no dashes, so splitting on the last dash is safe.
func parseBunFixtureFilename(base string) (version, arch string, ok bool) {
	stripped := strings.TrimSuffix(base, ".json")
	stripped = strings.TrimPrefix(stripped, "bun-")
	idx := strings.LastIndex(stripped, "-")
	if idx < 0 {
		return "", "", false
	}
	return stripped[:idx], stripped[idx+1:], true
}

// TestBunOffsets_AgainstReferenceJSON verifies that every committed reference
// JSON in tools/bun-offsets/results/ matches the corresponding row in
// bunOffsetTable. Runs as a plain Go test — no Docker, no network.
func TestBunOffsets_AgainstReferenceJSON(t *testing.T) {
	pattern := filepath.Join("..", "..", "tools", "bun-offsets", "results", "bun-*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %q: %v", pattern, err)
	}
	if len(paths) == 0 {
		t.Skipf("no reference JSONs at %s — run the bun-offsets discovery and commit results", pattern)
	}

	for _, p := range paths {
		base := filepath.Base(p)
		version, arch, ok := parseBunFixtureFilename(base)
		if !ok {
			t.Errorf("unparseable result filename: %s", base)
			continue
		}
		t.Run(fmt.Sprintf("%s-%s", version, arch), func(t *testing.T) {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			var ref bunReferenceJSON
			if err := json.Unmarshal(data, &ref); err != nil {
				t.Fatalf("parse %s: %v", p, err)
			}
			if ref.SSLWriteOffset == 0 {
				t.Fatalf("ssl_write_offset is zero in %s — re-run discovery", base)
			}
			if ref.BoringSSL.SSLToS3 == nil || ref.BoringSSL.S3ToAEAD == nil ||
				ref.BoringSSL.AEADToAESKey == nil || ref.BoringSSL.SSLToWBIO == nil {
				t.Fatalf("one or more BoringSSL offsets are null/missing in %s", base)
			}

			key := version + "/" + arch
			row, ok := bunOffsetTable[key]
			if !ok {
				t.Fatalf("bunOffsetTable has no row for %q — run apply-new-versions.sh", key)
			}
			if row.SSLWriteOffset != ref.SSLWriteOffset {
				t.Errorf("SSLWriteOffset mismatch: table=%d ref=%d", row.SSLWriteOffset, ref.SSLWriteOffset)
			}
			if row.BoringSSL.SSLToS3 != *ref.BoringSSL.SSLToS3 {
				t.Errorf("SSLToS3 mismatch: table=%d ref=%d", row.BoringSSL.SSLToS3, *ref.BoringSSL.SSLToS3)
			}
			if row.BoringSSL.S3ToAEAD != *ref.BoringSSL.S3ToAEAD {
				t.Errorf("S3ToAEAD mismatch: table=%d ref=%d", row.BoringSSL.S3ToAEAD, *ref.BoringSSL.S3ToAEAD)
			}
			if row.BoringSSL.AEADToAESKey != *ref.BoringSSL.AEADToAESKey {
				t.Errorf("AEADToAESKey mismatch: table=%d ref=%d", row.BoringSSL.AEADToAESKey, *ref.BoringSSL.AEADToAESKey)
			}
			if row.BoringSSL.SSLToWBIO != *ref.BoringSSL.SSLToWBIO {
				t.Errorf("SSLToWBIO mismatch: table=%d ref=%d", row.BoringSSL.SSLToWBIO, *ref.BoringSSL.SSLToWBIO)
			}
		})
	}
}

// TestBunOffsetTable_Sane guards against zero-valued rows in bunOffsetTable.
func TestBunOffsetTable_Sane(t *testing.T) {
	if len(bunOffsetTable) == 0 {
		t.Fatal("bunOffsetTable is empty")
	}
	for key, row := range bunOffsetTable {
		if row.SSLWriteOffset == 0 {
			t.Errorf("row %q: SSLWriteOffset is zero", key)
		}
		if row.BoringSSL.SSLToS3 == 0 || row.BoringSSL.S3ToAEAD == 0 ||
			row.BoringSSL.AEADToAESKey == 0 || row.BoringSSL.SSLToWBIO == 0 {
			t.Errorf("row %q: BoringSSL offsets have a zero field: %+v", key, row.BoringSSL)
		}
	}
}

// TestDetectBun_NotABunBinary confirms DetectBun returns false for non-Bun
// binaries (guards against false positives on OpenSSL/Go binaries).
func TestDetectBun_NotABunBinary(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "fake")
	if err := os.WriteFile(p, []byte("not a bun binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := DetectBun(p); ok {
		t.Error("DetectBun returned true for a non-Bun binary")
	}
}
