package main

import (
	"testing"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

func TestParseMaxSecretLength(t *testing.T) {
	for v, want := range map[string]int{
		"65536": 65536,
		"64Ki":  64 << 10,
		"1Mi":   secrets.MaxLenLimit,
		"128":   128,
		"8":     secrets.ShadowPrefixLen,
	} {
		if got, err := parseMaxSecretLength(v); err != nil || got != want {
			t.Errorf("parseMaxSecretLength(%q) = %d, %v, want %d", v, got, err, want)
		}
	}
	for _, v := range []string{"", "7", "0", "-1", "1Mi1", "2Mi", "1.5", "64KB", "1e12"} {
		if got, err := parseMaxSecretLength(v); err == nil {
			t.Errorf("parseMaxSecretLength(%q) = %d, want an error", v, got)
		}
	}
}

func TestParseByteQuantity(t *testing.T) {
	for v, want := range map[string]int64{"16Mi": 16 << 20, "1Gi": 1 << 30, "1000": 1000, "1k": 1000} {
		if got, err := parseByteQuantity(v); err != nil || got != want {
			t.Errorf("parseByteQuantity(%q) = %d, %v, want %d", v, got, err, want)
		}
	}
	for _, v := range []string{"", "abc", "0.5", "-1Mi", "100m"} {
		if got, err := parseByteQuantity(v); err == nil {
			t.Errorf("parseByteQuantity(%q) = %d, want an error", v, got)
		}
	}
}
