package ebpf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractGoMajorMinor(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"go1.25.1", "1.25"},
		{"go1.22", "1.22"},
		{"go1.21.0", "1.21"},
		{"go1.26.1", "1.26"},
		{"1.25", "1.25"},
	}
	for _, tt := range tests {
		got := extractGoMajorMinor(tt.input)
		if got != tt.want {
			t.Errorf("extractGoMajorMinor(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGoTLSOffsetTableEntries(t *testing.T) {
	// Verify all entries have non-zero offsets when resolved for amd64.
	for version, entry := range goTLSOffsetTableBase {
		if entry.ConnToCipher == 0 {
			t.Errorf("goTLSOffsetTableBase[%q].ConnToCipher is 0", version)
		}
		if entry.AEADIfaceOff == 0 {
			t.Errorf("goTLSOffsetTableBase[%q].AEADIfaceOff is 0", version)
		}
		if entry.PDBase == 0 {
			t.Errorf("goTLSOffsetTableBase[%q].PDBase is 0", version)
		}

		// Verify arch-specific resolution produces non-zero H2 offsets.
		for _, arch := range []string{"amd64", "arm64"} {
			offsets := goTLSOffsetsForArch(entry, arch)
			if offsets.H2HiOff == 0 {
				t.Errorf("goTLSOffsetsForArch(%q, %q).H2HiOff is 0", version, arch)
			}
			if offsets.H2LoOff == 0 {
				t.Errorf("goTLSOffsetsForArch(%q, %q).H2LoOff is 0", version, arch)
			}
			// Hi and Lo should differ by exactly 8 bytes.
			diff := int(offsets.H2HiOff) - int(offsets.H2LoOff)
			if diff != 8 && diff != -8 {
				t.Errorf("goTLSOffsetsForArch(%q, %q): H2HiOff=%d H2LoOff=%d, expected 8-byte difference",
					version, arch, offsets.H2HiOff, offsets.H2LoOff)
			}
		}
	}
}

func TestGoTLSOffsetsForArch(t *testing.T) {
	entry := goTLSOffsetEntry{ConnToCipher: 560, AEADIfaceOff: 24, PDBase: 728}

	amd64 := goTLSOffsetsForArch(entry, "amd64")
	// AMD64 PSHUFB: hi at +8, lo at +0
	if amd64.H2HiOff != 736 || amd64.H2LoOff != 728 {
		t.Errorf("amd64: H2HiOff=%d (want 736), H2LoOff=%d (want 728)", amd64.H2HiOff, amd64.H2LoOff)
	}

	arm64 := goTLSOffsetsForArch(entry, "arm64")
	// ARM64 VREV64: hi at +0, lo at +8
	if arm64.H2HiOff != 728 || arm64.H2LoOff != 736 {
		t.Errorf("arm64: H2HiOff=%d (want 728), H2LoOff=%d (want 736)", arm64.H2HiOff, arm64.H2LoOff)
	}
}

// referenceJSON matches the OffsetResult shape emitted by
// tools/go-tls-offsets/main.go. Subset of fields — we only assert on what
// the table needs to populate.
type referenceJSON struct {
	GoVersion    string `json:"go_version"`
	Arch         string `json:"arch"`
	ConnToCipher uint32 `json:"conn_to_cipher"`
	AEADIfaceOff uint32 `json:"aead_iface_off"`
	H2HiOff      uint32 `json:"h2_hi_off"`
	H2LoOff      uint32 `json:"h2_lo_off"`
	ConnVersOff  uint32 `json:"conn_vers_off"`
	Notes        string `json:"notes,omitempty"`
}

// parseFixtureFilename extracts (version, arch) from a `go-<v>-<arch>.json`
// or `go-<v>-<arch>.elf` filename.
func parseFixtureFilename(base string) (version, arch string, ok bool) {
	stripped := strings.TrimSuffix(strings.TrimSuffix(base, ".json"), ".elf")
	stripped = strings.TrimPrefix(stripped, "go-")
	idx := strings.LastIndex(stripped, "-")
	if idx < 0 {
		return "", "", false
	}
	return stripped[:idx], stripped[idx+1:], true
}

// TestGoTLSOffsets_AgainstReferenceJSON is the primary CI check: every
// committed reference JSON in tools/go-tls-offsets/results/ must agree with
// goTLSOffsetTableBase resolved through goTLSOffsetsForArch. Catches drift
// between the table and the canonical discovery output.
//
// Runs as a single Go test process, no Docker, no network — just file I/O.
// Subtests are named `<version>-<arch>` so failures point at exactly the
// (version, arch) cell that drifted.
func TestGoTLSOffsets_AgainstReferenceJSON(t *testing.T) {
	pattern := filepath.Join("..", "..", "tools", "go-tls-offsets", "results", "go-*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %q: %v", pattern, err)
	}
	if len(paths) == 0 {
		t.Skipf("no reference JSONs at %s — run `make go-tls-discover`", pattern)
	}

	for _, p := range paths {
		base := filepath.Base(p)
		version, arch, ok := parseFixtureFilename(base)
		if !ok {
			t.Errorf("unparseable result filename: %s", base)
			continue
		}
		t.Run(fmt.Sprintf("%s-%s", version, arch), func(t *testing.T) {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			var ref referenceJSON
			if err := json.Unmarshal(data, &ref); err != nil {
				t.Fatalf("parse %s: %v", p, err)
			}
			if ref.Notes != "" {
				t.Fatalf("reference JSON %s has notes=%q (the discovery tool reported missing offsets); regenerate via `make go-tls-discover`", base, ref.Notes)
			}

			majorMinor := extractGoMajorMinor(version)
			entry, ok := goTLSOffsetTableBase[majorMinor]
			if !ok {
				t.Fatalf("goTLSOffsetTableBase has no entry for Go %s — add it from %s", majorMinor, base)
			}
			got := goTLSOffsetsForArch(entry, arch)

			if got.ConnToCipher != ref.ConnToCipher {
				t.Errorf("ConnToCipher mismatch: table=%d ref=%d", got.ConnToCipher, ref.ConnToCipher)
			}
			if got.AEADIfaceOff != ref.AEADIfaceOff {
				t.Errorf("AEADIfaceOff mismatch: table=%d ref=%d", got.AEADIfaceOff, ref.AEADIfaceOff)
			}
			if got.H2HiOff != ref.H2HiOff {
				t.Errorf("H2HiOff mismatch: table=%d ref=%d", got.H2HiOff, ref.H2HiOff)
			}
			if got.H2LoOff != ref.H2LoOff {
				t.Errorf("H2LoOff mismatch: table=%d ref=%d", got.H2LoOff, ref.H2LoOff)
			}
			if got.ConnVersOff != ref.ConnVersOff {
				t.Errorf("ConnVersOff mismatch: table=%d ref=%d", got.ConnVersOff, ref.ConnVersOff)
			}
		})
	}
}

// TestGoTLSOffsets_AgainstFixtureDWARF is the deeper local check: it parses
// each ELF fixture's DWARF directly and confirms the result matches what
// the table produces. Validates the DWARF parser itself, not just
// table-vs-JSON equality. Skips when fixtures aren't present (the default
// in CI; developers running `make go-tls-fixtures` locally get this for free).
func TestGoTLSOffsets_AgainstFixtureDWARF(t *testing.T) {
	pattern := filepath.Join("..", "..", "pkg", "ebpf", "testdata", "go-tls-fixtures", "go-*.elf")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %q: %v", pattern, err)
	}
	if len(paths) == 0 {
		t.Skipf("no ELF fixtures at %s — run `make go-tls-fixtures`", pattern)
	}

	for _, p := range paths {
		base := filepath.Base(p)
		version, arch, ok := parseFixtureFilename(base)
		if !ok {
			t.Errorf("unparseable fixture filename: %s", base)
			continue
		}
		t.Run(fmt.Sprintf("%s-%s", version, arch), func(t *testing.T) {
			_, dwarfOffsets, err := detectGoTLSFromDWARF(p)
			if err != nil {
				t.Fatalf("detectGoTLSFromDWARF(%s): %v", base, err)
			}

			majorMinor := extractGoMajorMinor(version)
			entry, ok := goTLSOffsetTableBase[majorMinor]
			if !ok {
				t.Fatalf("goTLSOffsetTableBase has no entry for Go %s", majorMinor)
			}
			tableOffsets := goTLSOffsetsForArch(entry, arch)

			if dwarfOffsets.ConnToCipher != tableOffsets.ConnToCipher {
				t.Errorf("ConnToCipher: dwarf=%d table=%d", dwarfOffsets.ConnToCipher, tableOffsets.ConnToCipher)
			}
			if dwarfOffsets.AEADIfaceOff != tableOffsets.AEADIfaceOff {
				t.Errorf("AEADIfaceOff: dwarf=%d table=%d", dwarfOffsets.AEADIfaceOff, tableOffsets.AEADIfaceOff)
			}
			if dwarfOffsets.H2HiOff != tableOffsets.H2HiOff {
				t.Errorf("H2HiOff: dwarf=%d table=%d", dwarfOffsets.H2HiOff, tableOffsets.H2HiOff)
			}
			if dwarfOffsets.H2LoOff != tableOffsets.H2LoOff {
				t.Errorf("H2LoOff: dwarf=%d table=%d", dwarfOffsets.H2LoOff, tableOffsets.H2LoOff)
			}
			if dwarfOffsets.ConnVersOff != tableOffsets.ConnVersOff {
				t.Errorf("ConnVersOff: dwarf=%d table=%d", dwarfOffsets.ConnVersOff, tableOffsets.ConnVersOff)
			}
		})
	}
}
