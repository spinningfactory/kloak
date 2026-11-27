package ebpf

import (
	"errors"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

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

// bpfDurations reads nanosecond constants (#define NAME <n>ULL) from a BPF
// header of this package, every one of names required.
func bpfDurations(t *testing.T, file string, names ...string) (map[string]time.Duration, error) {
	t.Helper()
	src, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	out := map[string]time.Duration{}
	for _, name := range names {
		m := regexp.MustCompile(`(?m)^#define\s+` + name + `\s+(\d+)ULL\b`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("%s: no #define %s <n>ULL: update TestSecretStoreGraceCoversReaders", file, name)
		}
		ns, err := strconv.ParseInt(string(m[1]), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = time.Duration(ns)
	}
	return out, nil
}

// TestSecretStoreGraceCoversReaders checks that the secret store keeps a
// generation whole for longer than any data-plane reader may still use a
// reference to it, plus the margin (see secretStoreGrace): the TTLs are read
// from the BPF headers, the tc ledger's once it is in this package.
func TestSecretStoreGraceCoversReaders(t *testing.T) {
	staged, err := bpfDurations(t, "bpf/helpers.h", "XOR_PENDING_TTL_NS", "TC_PENDING_TTL_NS")
	if err != nil {
		t.Fatal(err)
	}
	longest := staged["XOR_PENDING_TTL_NS"] + staged["TC_PENDING_TTL_NS"]
	what := "XOR_PENDING_TTL_NS + TC_PENDING_TTL_NS"

	ledger, err := bpfDurations(t, "bpf/ledger_types.h", "LEDGER_REC_TTL_NS", "LEDGER_SLOT_TTL_NS")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		t.Log("no bpf/ledger_types.h (kloak#383 phase 2) yet: checked against the staged patches' TTLs")
	case err != nil:
		t.Fatal(err)
	default:
		// Both count from the uprobe's secret_map lookup
		// (ledger_slot.created_at).
		for _, name := range []string{"LEDGER_REC_TTL_NS", "LEDGER_SLOT_TTL_NS"} {
			if ledger[name] > longest {
				longest, what = ledger[name], name
			}
		}
	}
	if need := longest + secretStoreGraceMargin; secretStoreGrace < need {
		t.Errorf("secretStoreGrace is %v: a reference may be used for %v (%s), plus the %v margin: at least %v",
			secretStoreGrace, longest, what, secretStoreGraceMargin, need)
	}
}
