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
	// Verify all entries have non-zero H offset.
	for version, offsets := range goTLSOffsetTable {
		if offsets.ConnToCipher == 0 {
			t.Errorf("goTLSOffsetTable[%q].ConnToCipher is 0", version)
		}
		if offsets.AEADIfaceOff == 0 {
			t.Errorf("goTLSOffsetTable[%q].AEADIfaceOff is 0", version)
		}
		if offsets.GCMToH == 0 {
			t.Errorf("goTLSOffsetTable[%q].GCMToH is 0", version)
		}
	}
}
