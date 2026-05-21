package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestValidateHostsLabel(t *testing.T) {
	cases := []struct {
		name    string
		hosts   string
		wantErr string // substring; "" = no error
	}{
		{"empty", "", ""},
		{"single valid", "example.com", ""},
		{"wildcard", "*", ""},
		{"whitespace tolerated", "  api.example.com  ", ""},
		{"exactly 63 bytes", strings.Repeat("a", 63), ""},
		{"exactly 64 bytes rejected", strings.Repeat("a", 64), "exceeds max length"},
		{"multiple hosts rejected", "a.example.com,b.example.com", "multiple hosts are not supported"},
		{"csv with wildcard rejected", "*,api.example.com", "multiple hosts are not supported"},
		{"trailing comma rejected", "a.com,", "multiple hosts are not supported"},
		{"invalid DNS chars", "bad_host.com", "not a valid DNS name"},
		{"invalid leading dash", "-bad.com", "not a valid DNS name"},
		{"ipv4 address", "192.168.1.1", ""},
		{"ipv4 private range", "10.0.0.1", ""},
		{"ipv6 address", "2001:db8::1", ""},
		{"ipv6 loopback", "::1", ""},
		{"ipv4 loopback", "127.0.0.1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHostsLabel(tc.hosts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidatePortLabel(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		wantErr string
	}{
		{"empty", "", ""},
		{"port only", "443", ""},
		{"port tcp", "443/tcp", ""},
		{"port udp", "53/udp", ""},
		{"whitespace", "  443/tcp  ", ""},
		{"upper proto", "443/TCP", ""},
		{"port zero", "0", "must be in range"},
		{"port overflow", "70000", "invalid port"},
		{"port non-numeric", "abc", "invalid port"},
		{"bad proto", "443/sctp", "invalid proto"},
		{"too many slashes", "443/tcp/extra", "invalid format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePortLabel(tc.spec)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateSecretData(t *testing.T) {
	cases := []struct {
		name       string
		data       map[string][]byte
		stringData map[string]string
		wantErr    string
	}{
		{"empty rejected", nil, nil, "no data entries"},
		// PASS1234 (49 Huffman bits) sits comfortably inside the
		// kl::-prefix feasibility window [47, 55] at length 8 — the
		// CanShadow check accepts it. Earlier "12345678" (46 bits) is
		// 1 bit below the floor, used below to exercise the rejection
		// path.
		{"min length accepted", map[string][]byte{"k": []byte("PASS1234")}, nil, ""},
		// 128 bytes of "Test1234" repeat. Density ≈5.25 b/B, total
		// 672 Huffman bits, comfortably inside window [647, 895].
		{"max length accepted", map[string][]byte{"k": []byte(strings.Repeat("Test1234", 16))}, nil, ""},
		{"too short rejected", map[string][]byte{"k": []byte("short")}, nil, "minimum 8"},
		{"too long rejected", map[string][]byte{"k": make([]byte, 129)}, nil, "maximum 128"},
		// Huffman feasibility check: "12345678" at length 8 is 46 bits,
		// one below the window's lower bound. Without this rejection at
		// admission time, the reconciler would silently fail to mint a
		// shadow and leave the user's app unprotected on the wire.
		{"infeasible density rejected", map[string][]byte{"k": []byte("12345678")}, nil, "outside the range kloak can shadow"},
		{"valid stringData", nil, map[string]string{"k": "PASS1234"}, ""},
		{"short stringData rejected", nil, map[string]string{"k": "abc"}, "minimum 8"},
		{"stringData overrides data (longer wins when keys match)",
			map[string][]byte{"k": []byte("short")}, // would fail on its own
			map[string]string{"k": "PASS1234"},      // valid
			""},
		{"mixed keys, one bad",
			map[string][]byte{"good": []byte("PASS1234")},
			map[string]string{"bad": "x"},
			"minimum 8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSecretData(tc.data, tc.stringData)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestSecretValidator_Handle(t *testing.T) {
	logger := zap.NewNop().Sugar()
	v := NewSecretValidator(logger)

	build := func(labels map[string]string, annotations map[string]string, data map[string][]byte) admission.Request {
		s := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: metav1.ObjectMeta{
				Name:        "s",
				Namespace:   "default",
				Labels:      labels,
				Annotations: annotations,
			},
			Data: data,
		}
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return admission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Object: runtime.RawExtension{Raw: raw},
			},
		}
	}

	validData := map[string][]byte{"api-key": []byte("super-secret-token")}

	cases := []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		data        map[string][]byte
		wantAllow   bool
		wantReason  string
	}{
		{
			name:        "not kloak-enabled is allowed regardless of other fields",
			labels:      nil,
			annotations: map[string]string{AnnotationHosts: strings.Repeat("a", 70)},
			data:        nil,
			wantAllow:   true,
		},
		{
			name:        "enabled with valid annotations and data",
			labels:      map[string]string{LabelEnabled: "true"},
			annotations: map[string]string{AnnotationHosts: "api.example.com", AnnotationPort: "443/tcp"},
			data:        validData,
			wantAllow:   true,
		},
		{
			name:        "enabled with ipv4 host accepted",
			labels:      map[string]string{LabelEnabled: "true"},
			annotations: map[string]string{AnnotationHosts: "192.168.1.1", AnnotationPort: "443/tcp"},
			data:        validData,
			wantAllow:   true,
		},
		{
			name:        "enabled with ipv6 host accepted",
			labels:      map[string]string{LabelEnabled: "true"},
			annotations: map[string]string{AnnotationHosts: "2001:db8::1", AnnotationPort: "443/tcp"},
			data:        validData,
			wantAllow:   true,
		},
		{
			name:        "enabled with too-long host denied",
			labels:      map[string]string{LabelEnabled: "true"},
			annotations: map[string]string{AnnotationHosts: strings.Repeat("a", 64)},
			data:        validData,
			wantAllow:   false,
			wantReason:  "exceeds max length",
		},
		{
			name:        "enabled with bad port denied",
			labels:      map[string]string{LabelEnabled: "true"},
			annotations: map[string]string{AnnotationPort: "abc"},
			data:        validData,
			wantAllow:   false,
			wantReason:  "invalid port",
		},
		{
			name:        "enabled with empty data denied",
			labels:      map[string]string{LabelEnabled: "true"},
			annotations: nil,
			data:        nil,
			wantAllow:   false,
			wantReason:  "no data entries",
		},
		{
			name:        "enabled with short data denied",
			labels:      map[string]string{LabelEnabled: "true"},
			annotations: nil,
			data:        map[string][]byte{"k": []byte("short")},
			wantAllow:   false,
			wantReason:  "minimum 8",
		},
		{
			name:        "enabled with oversize data denied",
			labels:      map[string]string{LabelEnabled: "true"},
			annotations: nil,
			data:        map[string][]byte{"k": make([]byte, 200)},
			wantAllow:   false,
			wantReason:  "maximum 128",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := v.Handle(context.Background(), build(tc.labels, tc.annotations, tc.data))
			if resp.Allowed != tc.wantAllow {
				t.Fatalf("allowed=%v want=%v (msg=%q)", resp.Allowed, tc.wantAllow, resp.Result.Message)
			}
			if !tc.wantAllow && !strings.Contains(resp.Result.Message, tc.wantReason) {
				t.Fatalf("expected reason %q in %q", tc.wantReason, resp.Result.Message)
			}
		})
	}
}
