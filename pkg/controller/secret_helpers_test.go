package controller

import (
	"testing"
)

// TestIsPrefixUsed exercises the intra-Reconcile collision check that
// guards against two data keys in the same Secret accidentally landing
// on the same 8-byte BPF prefix. (Cross-secret collisions are handled
// by secrets.ShadowGenerator and tested in pkg/secrets.)
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
		// Shadows shorter than the prefix length are skipped; the function
		// never panics on slicing.
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
