package ebpf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractMajorMinor(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"3.2.1", "3.2"},
		{"3.0.13", "3.0"},
		{"1.1.1w", "1.1"},
		{"3", "3"},
		{"3.4", "3.4"},
	}
	for _, tt := range tests {
		got := extractMajorMinor(tt.input)
		if got != tt.want {
			t.Errorf("extractMajorMinor(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestOpensslOffsetTable_SSLToWBIO(t *testing.T) {
	// Every entry in the table must carry a non-zero SSLToWBIO — a zero
	// is the BPF data plane's sentinel for "fall back to the hardcoded
	// 88", which silently regresses 3.0/3.1 callers. The specific values
	// here were verified empirically (3.0.13: SSL_set_bio + pointer scan
	// returned wbio at offset 24; 3.2+: ssl_connection_st.wbio = 88) and
	// must not drift without re-verification.
	cases := []struct {
		majMin string
		want   uint32
	}{
		// 3-hop chain — bare ssl_st, wbio is the second BIO field after rbio.
		{"3.0", 24},
		{"3.1", 24},
		// 4-hop chain — ssl_connection_st wrapper relocated wbio to 88.
		{"3.2", 88},
		{"3.3", 88},
		{"3.4", 88},
		{"3.5", 88},
	}
	for _, c := range cases {
		got, ok := opensslOffsetTable[c.majMin]
		if !ok {
			t.Fatalf("opensslOffsetTable missing %q", c.majMin)
		}
		if got.SSLToWBIO != c.want {
			t.Errorf("opensslOffsetTable[%q].SSLToWBIO = %d, want %d "+
				"(if this is intentional, update the test and confirm via pahole or "+
				"SSL_set_bio + pointer scan against a real libssl of this version)",
				c.majMin, got.SSLToWBIO, c.want)
		}
	}

	// Defensive: any future entry added to the table must also include a
	// non-zero SSLToWBIO. A zero would trip the BPF fallback to 88 and
	// silently break workloads on that version.
	for k, v := range opensslOffsetTable {
		if v.SSLToWBIO == 0 {
			t.Errorf("opensslOffsetTable[%q] has SSLToWBIO=0 — verify and set explicitly", k)
		}
	}
}

// opensslReferenceJSON mirrors the kloak_config section emitted by
// tools/openssl-offsets/extract_offsets.sh for a single (version, arch) cell.
// Pointer types distinguish null (extraction failed) from 0 (valid zero offset).
type opensslReferenceJSON struct {
	OpenSSLVersion string `json:"openssl_version"`
	Arch           string `json:"arch"`
	// VAESHKey1Status is "ok", "not_applicable" (no AVX-512 GCM path) or
	// "unrecognized" (asm layout changed — HashKey_1 recovery disabled).
	VAESHKey1Status string `json:"vaes_hkey1_status"`
	KloakConfig     struct {
		SSLToWRL          *uint32 `json:"SSLToWRL"`
		WRLToEncCtx       *uint32 `json:"WRLToEncCtx"`
		EncCtxToAlgctx    *uint32 `json:"EncCtxToAlgctx"`
		AlgctxToH         *uint32 `json:"AlgctxToH"`
		SSLToVersion      *uint32 `json:"SSLToVersion"`
		SSLToWBIO         *uint32 `json:"SSLToWBIO"`
		AlgctxToGCMKey    *uint32 `json:"AlgctxToGCMKey"`
		AlgctxToKeySched  *uint32 `json:"AlgctxToKeySched"`
		AlgctxToVAESHKey1 *uint32 `json:"AlgctxToVAESHKey1"`
	} `json:"kloak_config"`
}

// parseOpenSSLFixtureFilename extracts (version, arch) from an
// openssl-<version>-<arch>.json filename.
func parseOpenSSLFixtureFilename(base string) (version, arch string, ok bool) {
	stripped := strings.TrimSuffix(base, ".json")
	stripped = strings.TrimPrefix(stripped, "openssl-")
	idx := strings.LastIndex(stripped, "-")
	if idx < 0 {
		return "", "", false
	}
	return stripped[:idx], stripped[idx+1:], true
}

// TestOpenSSLOffsets_AgainstReferenceJSON is the primary CI check for OpenSSL
// offsets: every committed reference JSON in tools/openssl-offsets/results/
// must agree with opensslOffsetTable. Catches drift between the static table
// and the canonical discovery output (tools/openssl-offsets/extract_offsets.sh).
//
// Runs as a plain Go test — no Docker, no network. Subtests are named
// <version>-<arch> so failures pinpoint the exact cell that drifted.
//
// If SSLToVersion in the table is 0xFFFFFFFF (sentinel for "not yet verified,
// use BPF heuristic") but the JSON has a real offset, update the table entry
// with the discovered value and remove the sentinel.
func TestOpenSSLOffsets_AgainstReferenceJSON(t *testing.T) {
	pattern := filepath.Join("..", "..", "tools", "openssl-offsets", "results", "openssl-*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %q: %v", pattern, err)
	}
	if len(paths) == 0 {
		t.Skipf("no reference JSONs at %s — run the openssl-offsets workflow and commit results", pattern)
	}

	for _, p := range paths {
		base := filepath.Base(p)
		version, arch, ok := parseOpenSSLFixtureFilename(base)
		if !ok {
			t.Errorf("unparseable result filename: %s", base)
			continue
		}
		t.Run(fmt.Sprintf("%s-%s", version, arch), func(t *testing.T) {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			var ref opensslReferenceJSON
			if err := json.Unmarshal(data, &ref); err != nil {
				t.Fatalf("parse %s: %v", p, err)
			}

			majorMinor := extractMajorMinor(version)
			entry, ok := opensslOffsetTable[majorMinor]
			if !ok {
				t.Fatalf("opensslOffsetTable has no entry for OpenSSL %s — add it from %s", majorMinor, base)
			}

			if ref.KloakConfig.SSLToWRL == nil || ref.KloakConfig.WRLToEncCtx == nil ||
				ref.KloakConfig.EncCtxToAlgctx == nil || ref.KloakConfig.AlgctxToH == nil ||
				ref.KloakConfig.SSLToVersion == nil || ref.KloakConfig.SSLToWBIO == nil ||
				ref.KloakConfig.AlgctxToGCMKey == nil || ref.KloakConfig.AlgctxToKeySched == nil ||
				ref.KloakConfig.AlgctxToVAESHKey1 == nil {
				t.Fatalf("one or more offsets are null/missing in reference JSON %s — re-run discovery", base)
			}

			// The data plane inverts HashKey_1 only for the AVX-512 GCM layout
			// discovery verified; anything else must keep recovery disabled.
			switch ref.VAESHKey1Status {
			case "ok":
				if *ref.KloakConfig.AlgctxToVAESHKey1 == 0 {
					t.Errorf("vaes_hkey1_status=ok but AlgctxToVAESHKey1=0 in %s", base)
				}
			case "not_applicable":
				if *ref.KloakConfig.AlgctxToVAESHKey1 != 0 {
					t.Errorf("vaes_hkey1_status=not_applicable but AlgctxToVAESHKey1=%d in %s", *ref.KloakConfig.AlgctxToVAESHKey1, base)
				}
			case "unrecognized":
				t.Errorf("%s: OpenSSL's AVX-512 GCM layout was not recognised by discovery, so "+
					"HashKey_1 recovery is disabled and OpenSSL %s cannot be rewritten on AVX-512+VAES CPUs. "+
					"Review crypto/modes/asm/aes-gcm-avx512.pl against gf128_halve_to_h and update "+
					"tools/openssl-offsets/extract_offsets.sh", base, version)
			default:
				t.Errorf("unexpected vaes_hkey1_status %q in %s — re-run discovery", ref.VAESHKey1Status, base)
			}

			if entry.SSLToWRL != *ref.KloakConfig.SSLToWRL {
				t.Errorf("SSLToWRL mismatch: table=%d ref=%d", entry.SSLToWRL, *ref.KloakConfig.SSLToWRL)
			}
			if entry.WRLToEncCtx != *ref.KloakConfig.WRLToEncCtx {
				t.Errorf("WRLToEncCtx mismatch: table=%d ref=%d", entry.WRLToEncCtx, *ref.KloakConfig.WRLToEncCtx)
			}
			if entry.EncCtxToAlgctx != *ref.KloakConfig.EncCtxToAlgctx {
				t.Errorf("EncCtxToAlgctx mismatch: table=%d ref=%d", entry.EncCtxToAlgctx, *ref.KloakConfig.EncCtxToAlgctx)
			}
			if entry.AlgctxToH != *ref.KloakConfig.AlgctxToH {
				t.Errorf("AlgctxToH mismatch: table=%d ref=%d", entry.AlgctxToH, *ref.KloakConfig.AlgctxToH)
			}
			// SSLToVersion: 0xFFFFFFFF in the table means "not yet verified, BPF uses
			// heuristic". If the JSON has a real offset, update the table entry.
			if entry.SSLToVersion != 0xFFFFFFFF && entry.SSLToVersion != *ref.KloakConfig.SSLToVersion {
				t.Errorf("SSLToVersion mismatch: table=%d ref=%d", entry.SSLToVersion, *ref.KloakConfig.SSLToVersion)
			}
			if entry.SSLToVersion == 0xFFFFFFFF && *ref.KloakConfig.SSLToVersion != 0xFFFFFFFF {
				t.Logf("SSLToVersion for %s is unverified (table=0xFFFFFFFF); discovered offset=%d — update opensslOffsetTable", majorMinor, *ref.KloakConfig.SSLToVersion)
			}
			if entry.SSLToWBIO != *ref.KloakConfig.SSLToWBIO {
				t.Errorf("SSLToWBIO mismatch: table=%d ref=%d", entry.SSLToWBIO, *ref.KloakConfig.SSLToWBIO)
			}
			if entry.AlgctxToGCMKey != *ref.KloakConfig.AlgctxToGCMKey {
				t.Errorf("AlgctxToGCMKey mismatch: table=%d ref=%d", entry.AlgctxToGCMKey, *ref.KloakConfig.AlgctxToGCMKey)
			}
			if entry.AlgctxToKeySched != *ref.KloakConfig.AlgctxToKeySched {
				t.Errorf("AlgctxToKeySched mismatch: table=%d ref=%d", entry.AlgctxToKeySched, *ref.KloakConfig.AlgctxToKeySched)
			}
			if entry.AlgctxToVAESHKey1 != *ref.KloakConfig.AlgctxToVAESHKey1 {
				t.Errorf("AlgctxToVAESHKey1 mismatch: table=%d ref=%d", entry.AlgctxToVAESHKey1, *ref.KloakConfig.AlgctxToVAESHKey1)
			}
		})
	}
}

// TestOpensslOffsetTable_GCMGate checks the invariants ossl_read_gcm_h relies
// on: every row is gated (so garbage at AlgctxToH in a non-GCM context is never
// taken for H), and HashKey_1 recovery is only enabled behind that gate.
func TestOpensslOffsetTable_GCMGate(t *testing.T) {
	for v, o := range opensslOffsetTable {
		if o.AlgctxToGCMKey == 0 || o.AlgctxToKeySched == 0 {
			t.Errorf("%s: GCM gate offsets not calibrated (AlgctxToGCMKey=%d AlgctxToKeySched=%d)",
				v, o.AlgctxToGCMKey, o.AlgctxToKeySched)
		}
		if o.AlgctxToGCMKey == o.AlgctxToH || o.AlgctxToVAESHKey1 == o.AlgctxToH {
			t.Errorf("%s: gate/HashKey_1 offset aliases the raw H field (%d)", v, o.AlgctxToH)
		}
	}
}

func TestFindVersionInData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "standard format",
			data: []byte("some data\x00OpenSSL 3.2.1 14 Jan 2025\x00more"),
			want: "3.2.1",
		},
		{
			name: "null terminated",
			data: []byte("OpenSSL 3.0.13\x00"),
			want: "3.0.13",
		},
		{
			name: "not present",
			data: []byte("BoringSSL something"),
			want: "",
		},
		{
			name: "partial match",
			data: []byte("OpenSSL "),
			want: "",
		},
		{
			name: "old format",
			data: []byte("OpenSSL 1.1.1w  11 Sep 2023\x00"),
			want: "1.1.1w",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findVersionInData(tt.data)
			if got != tt.want {
				t.Errorf("findVersionInData() = %q, want %q", got, tt.want)
			}
		})
	}
}
