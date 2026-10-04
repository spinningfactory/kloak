package ebpf

import "testing"

func TestParseTCAttachMode(t *testing.T) {
	cases := []struct {
		in      string
		want    TCAttachMode
		wantErr bool
	}{
		{"", TCAttachAuto, false},
		{"auto", TCAttachAuto, false},
		{" TCX ", TCAttachTCX, false},
		{"clsact", TCAttachClsact, false},
		{"legacy", "", true},
		{"tc", "", true},
	}
	for _, tc := range cases {
		got, err := ParseTCAttachMode(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ParseTCAttachMode(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("ParseTCAttachMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
