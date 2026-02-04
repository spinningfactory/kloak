package hash

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	hash := Generate("my-secret-value")

	// SHA256 produces 64 hex characters
	if len(hash) != 64 {
		t.Fatalf("Expected 64 char hash, got %d", len(hash))
	}

	// Same input should produce same hash
	hash2 := Generate("my-secret-value")
	if hash != hash2 {
		t.Fatal("Same input should produce same hash")
	}

	// Different input should produce different hash
	hash3 := Generate("different-value")
	if hash == hash3 {
		t.Fatal("Different input should produce different hash")
	}
}

func TestGenerateWithPrefix(t *testing.T) {
	hash := GenerateWithPrefix("my-secret")

	if len(hash) != 72 { // 8 (prefix) + 64 (hash)
		t.Fatalf("Expected 72 char hash with prefix, got %d", len(hash))
	}

	if hash[:8] != "bouncer:" {
		t.Fatalf("Expected 'bouncer:' prefix, got '%s'", hash[:8])
	}
}

func TestIsBouncerHash(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{Generate("test"), true},                           // Raw SHA256
		{GenerateWithPrefix("test"), true},                 // With prefix
		{"short", false},                                   // Too short
		{"not-a-hash-at-all-but-long-enough-maybe", false}, // Not hex
		{"", false}, // Empty
	}

	for _, tc := range tests {
		result := IsBouncerHash(tc.input)
		if result != tc.expected {
			t.Errorf("IsBouncerHash(%q) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}
