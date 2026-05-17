package ebpf

import "testing"

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
