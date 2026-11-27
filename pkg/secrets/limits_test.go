package secrets

import "testing"

func TestEffectiveMaxLen(t *testing.T) {
	for _, c := range []struct {
		policy, want int
	}{
		{DefaultMaxLen, DataPlaneMaxLen},
		{MaxLenLimit, DataPlaneMaxLen},
		{MaxLenLimit + 1, DataPlaneMaxLen},
		{DataPlaneMaxLen, DataPlaneMaxLen},
		{DataPlaneMaxLen - 1, DataPlaneMaxLen - 1},
		{64, 64},
		{ShadowPrefixLen, ShadowPrefixLen},
		{0, ShadowPrefixLen},
		{-1, ShadowPrefixLen},
	} {
		if got := EffectiveMaxLen(c.policy); got != c.want {
			t.Errorf("EffectiveMaxLen(%d) = %d, want %d", c.policy, got, c.want)
		}
	}
}

func TestValidateMaxLen(t *testing.T) {
	for _, ok := range []int{ShadowPrefixLen, DataPlaneMaxLen, DefaultMaxLen, MaxLenLimit} {
		if err := ValidateMaxLen(ok); err != nil {
			t.Errorf("ValidateMaxLen(%d): %v", ok, err)
		}
	}
	for _, bad := range []int{-1, 0, ShadowPrefixLen - 1, MaxLenLimit + 1} {
		if err := ValidateMaxLen(bad); err == nil {
			t.Errorf("ValidateMaxLen(%d) accepted", bad)
		}
	}
}
