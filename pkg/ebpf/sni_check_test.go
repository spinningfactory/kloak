package ebpf

import "testing"

func TestParseSNICheckMode(t *testing.T) {
	cases := []struct {
		in      string
		want    SNICheckMode
		wantErr bool
	}{
		{"", SNICheckEnforce, false},
		{"enforce", SNICheckEnforce, false},
		{" Audit ", SNICheckAudit, false},
		{"off", "", true},
	}
	for _, tc := range cases {
		got, err := ParseSNICheckMode(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseSNICheckMode(%q) = (%q, %v), want (%q, err=%v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
	if SNICheckEnforce.bpfValue() != sniCheckModeEnforce || SNICheckAudit.bpfValue() != sniCheckModeAudit {
		t.Error("bpfValue does not match SNI_CHECK_* in tls_uprobe.c")
	}
}

func TestDescribeSNIEvent(t *testing.T) {
	ev := secretBindingEvent{Reason: secretEventSNI, SNIStatus: 6}
	copy(ev.SNI[:], "evil.example")
	reason, sni := describeSNIEvent(&ev)
	if reason != "SNI does not match the secret's host" || sni != "evil.example" {
		t.Errorf("describeSNIEvent = (%q, %q)", reason, sni)
	}

	reason, sni = describeSNIEvent(&secretBindingEvent{Reason: secretEventSNI, SNIStatus: 0})
	if reason != "no ClientHello seen on the connection" || sni != "" {
		t.Errorf("describeSNIEvent(no state) = (%q, %q)", reason, sni)
	}
}
