// Package hash provides utilities for generating and managing
// SHA256 hashes used for environment variable obfuscation.
package hash

import (
	"crypto/sha256"
	"encoding/hex"
)

// Generate creates a SHA256 hash of the input value.
// Returns a hex-encoded string.
func Generate(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

// GenerateWithPrefix creates a SHA256 hash with a prefix for identification.
// The prefix helps identify kloak-managed values during debugging.
func GenerateWithPrefix(value string) string {
	return "kloak:" + Generate(value)
}

// IsKloakHash checks if a value looks like a kloak-generated hash.
func IsKloakHash(value string) bool {
	if len(value) < 6 {
		return false
	}
	// Check for prefix ("kloak:" = 6 chars + 64 hash = 70 total)
	if len(value) == 70 && value[:6] == "kloak:" {
		return true
	}
	// Check for raw SHA256 (64 hex chars)
	if len(value) == 64 {
		return isHex(value)
	}
	return false
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
