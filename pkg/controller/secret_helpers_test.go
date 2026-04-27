package controller

import (
	"strings"
	"testing"
)

// helpersIsPrefixUsed and helpersCheckCollisionsWithMap target the two unexported
// helpers that drive shadow-secret prefix uniqueness. They have no external state
// and are easy to exercise in isolation; the existing reconciler tests don't
// cover them directly.

func TestIsPrefixUsed(t *testing.T) {
	cases := []struct {
		name    string
		shadows []string
		prefix  string
		want    bool
	}{
		{"empty list", nil, "kloak:AB", false},
		{"present at head", []string{"kloak:AB12345-rest"}, "kloak:AB", true},
		{"present in middle", []string{"kloak:XX12345", "kloak:AB23456", "kloak:CC34567"}, "kloak:AB", true},
		{"missing", []string{"kloak:AA12345", "kloak:BB23456"}, "kloak:CC", false},
		// Shadows shorter than ShadowPrefixLen are skipped; the function never
		// panics on slicing.
		{"shadow shorter than prefix", []string{"short", "kloak:AB12345"}, "kloak:AB", true},
		// All entries too short → no match.
		{"all short", []string{"a", "bc", "def"}, "kloak:AB", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isPrefixUsed(tc.shadows, tc.prefix)
			if got != tc.want {
				t.Errorf("isPrefixUsed(%v, %q) = %v, want %v", tc.shadows, tc.prefix, got, tc.want)
			}
		})
	}
}

func TestCheckCollisionsWithMap(t *testing.T) {
	const prefix = "kloak:AB" // must be exactly ShadowPrefixLen bytes
	const newShadow = prefix + "12345xyz"

	t.Run("no entry for prefix", func(t *testing.T) {
		m := map[string]map[string]struct{}{}
		if checkCollisionsWithMap(newShadow, "ns/secret-a", m) {
			t.Error("expected false when prefix has no entry")
		}
	})

	t.Run("prefix used only by excluded secret", func(t *testing.T) {
		// The same secret can re-occupy its own prefix without colliding.
		m := map[string]map[string]struct{}{
			prefix: {"ns/secret-a": {}},
		}
		if checkCollisionsWithMap(newShadow, "ns/secret-a", m) {
			t.Error("expected false when only the excluded secret uses the prefix")
		}
	})

	t.Run("prefix used by different secret → collision", func(t *testing.T) {
		m := map[string]map[string]struct{}{
			prefix: {"ns/secret-other": {}},
		}
		if !checkCollisionsWithMap(newShadow, "ns/secret-a", m) {
			t.Error("expected true when a different secret uses the prefix")
		}
	})

	t.Run("prefix used by excluded + different secret → collision", func(t *testing.T) {
		m := map[string]map[string]struct{}{
			prefix: {
				"ns/secret-a":      {},
				"ns/secret-other":  {},
			},
		}
		if !checkCollisionsWithMap(newShadow, "ns/secret-a", m) {
			t.Error("expected collision when any other secret shares the prefix")
		}
	})

	t.Run("longer shadow uses leading prefix only", func(t *testing.T) {
		// The function slices [:ShadowPrefixLen] off newShadow, so a longer
		// shadow with the same leading 8 bytes still collides.
		long := prefix + strings.Repeat("z", 40)
		m := map[string]map[string]struct{}{
			prefix: {"ns/other": {}},
		}
		if !checkCollisionsWithMap(long, "ns/self", m) {
			t.Error("expected collision based on leading 8 bytes")
		}
	})
}
