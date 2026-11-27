package ebpf

import (
	"testing"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

func TestSecretStoreConfig(t *testing.T) {
	var def SecretStoreConfig
	if err := def.Validate(); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
	if got, want := def.chunkEntries(), uint32(DefaultSecretStoreBytes/secretChunkEntryBytes); got != want || got < 2*4096 {
		t.Errorf("default budget: %d chunks, want %d, at least two for each of secret_map's 4096 entries", got, want)
	}
	if got := def.maxLen(); got != secrets.DataPlaneMaxLen {
		t.Errorf("default max length %d, want the data plane's %d", got, secrets.DataPlaneMaxLen)
	}
	if got := (SecretStoreConfig{MaxSecretLen: 64}).maxLen(); got != 64 {
		t.Errorf("a policy of 64 bytes: max length %d", got)
	}
	for _, bad := range []SecretStoreConfig{
		{Bytes: MinSecretStoreBytes - 1},
		{Bytes: MaxSecretStoreBytes + 1},
		{Bytes: -1},
		{MaxSecretLen: secrets.MaxLenLimit + 1},
		{MaxSecretLen: secrets.ShadowPrefixLen - 1},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	for _, ok := range []SecretStoreConfig{{Bytes: MinSecretStoreBytes}, {Bytes: MaxSecretStoreBytes, MaxSecretLen: secrets.MaxLenLimit}} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
}
