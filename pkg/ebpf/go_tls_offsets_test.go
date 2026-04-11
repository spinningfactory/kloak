package ebpf

import "testing"

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
