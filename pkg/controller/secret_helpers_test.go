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
		// Prefixes are ShadowPrefixLen=8 bytes; "kl::" (4) + 4 random chars.
		{"empty list", nil, "kl::ABcd", false},
		{"present at head", []string{"kl::ABcd2345-rest"}, "kl::ABcd", true},
		{"present in middle", []string{"kl::XXyy2345", "kl::ABcd3456", "kl::CCdd4567"}, "kl::ABcd", true},
		{"missing", []string{"kl::AAaa2345", "kl::BBbb3456"}, "kl::CCcc", false},
		// Shadows shorter than the prefix length are skipped; the function
		// never panics on slicing.
		{"shadow shorter than prefix", []string{"short", "kl::ABcd2345"}, "kl::ABcd", true},
		// All entries too short → no match.
		{"all short", []string{"a", "bc", "def"}, "kl::ABcd", false},
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
