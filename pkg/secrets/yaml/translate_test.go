package yaml

import (
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// newGen returns a fresh ShadowGenerator with an empty seed. Used by
// every translator test so name-derived OwnerIDs are the only thing
// the collision tracker sees.
func newGen() *secrets.ShadowGenerator { return secrets.NewShadowGenerator(nil, nil) }

func TestTranslate_SingleSecretLiteralValue(t *testing.T) {
	spec := fileSpec{Secrets: []secretSpec{{
		Name:   "stripe-key",
		Value:  "sk-live-xyz",
		Host:   "api.stripe.com",
		Port:   "443",
		Inject: injectSpec{Env: "STRIPE_KEY"},
	}}}

	out, err := translate(spec, newGen())
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("len(out)=%d, want 1", len(out))
	}
	got := out[0]
	if got.OwnerID != "stripe-key" || got.Key != "stripe-key" {
		t.Errorf("OwnerID=%q Key=%q, want both =stripe-key", got.OwnerID, got.Key)
	}
	if got.Real != "sk-live-xyz" {
		t.Errorf("Real=%q, want sk-live-xyz", got.Real)
	}
	if !strings.HasPrefix(got.Shadow, secrets.ValuePrefix) {
		t.Errorf("Shadow=%q does not start with %q", got.Shadow, secrets.ValuePrefix)
	}
	if len(got.Shadow) != len(got.Real) {
		t.Errorf("len(Shadow)=%d, want %d (= len(Real))", len(got.Shadow), len(got.Real))
	}
	if got.Host != "api.stripe.com" || got.IP != nil {
		t.Errorf("Host=%q IP=%v, want api.stripe.com + nil", got.Host, got.IP)
	}
	if got.Port != 443 || got.Protocol != uint8(unix.IPPROTO_TCP) {
		t.Errorf("Port=%d Protocol=%d, want 443/tcp", got.Port, got.Protocol)
	}
	if got.Inject.Env != "STRIPE_KEY" || got.Inject.File != "" {
		t.Errorf("Inject=%+v, want {Env:STRIPE_KEY}", got.Inject)
	}
}

func TestTranslate_HostParsedAsLiteralIP(t *testing.T) {
	// ParseHost routes a literal IP into the IP field, leaving Host empty.
	// The translator should propagate that unchanged.
	spec := fileSpec{Secrets: []secretSpec{{
		Name:   "lan-key",
		Value:  "fixture-real-mid",
		Host:   "192.0.2.7",
		Inject: injectSpec{File: "/run/kloak/lan"},
	}}}
	out, err := translate(spec, newGen())
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if out[0].Host != "" {
		t.Errorf("Host=%q, want empty when input is a literal IP", out[0].Host)
	}
	if !out[0].IP.Equal(net.ParseIP("192.0.2.7")) {
		t.Errorf("IP=%v, want 192.0.2.7", out[0].IP)
	}
}

func TestTranslate_ValueFromEnv(t *testing.T) {
	t.Setenv("KLOAK_TEST_REAL", "from-env-real-val")
	spec := fileSpec{Secrets: []secretSpec{{
		Name:      "vf",
		ValueFrom: &valueFromSpec{Env: "KLOAK_TEST_REAL"},
		Inject:    injectSpec{Env: "VF"},
	}}}
	out, err := translate(spec, newGen())
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if out[0].Real != "from-env-real-val" {
		t.Errorf("Real=%q, want from-env-real-val", out[0].Real)
	}
}

func TestTranslate_ValueFromEnvMissingErrors(t *testing.T) {
	// `valueFrom.env: …` referencing an unset env var must error rather
	// than silently producing an empty real value.
	spec := fileSpec{Secrets: []secretSpec{{
		Name:      "vf",
		ValueFrom: &valueFromSpec{Env: "KLOAK_TEST_UNSET_VAR_DO_NOT_DEFINE"},
		Inject:    injectSpec{Env: "VF"},
	}}}
	_, err := translate(spec, newGen())
	if err == nil {
		t.Fatal("expected error for missing valueFrom.env, got nil")
	}
	if !strings.Contains(err.Error(), "valueFrom.env") {
		t.Errorf("error %q should mention valueFrom.env", err)
	}
}

func TestTranslate_ValidationRules(t *testing.T) {
	cases := []struct {
		name    string
		spec    fileSpec
		wantSub string // substring expected in error
	}{
		{
			name:    "empty list",
			spec:    fileSpec{},
			wantSub: "no secrets defined",
		},
		{
			name:    "missing name",
			spec:    fileSpec{Secrets: []secretSpec{{Value: "v", Inject: injectSpec{Env: "E"}}}},
			wantSub: "`name` is required",
		},
		{
			name: "duplicate name",
			spec: fileSpec{Secrets: []secretSpec{
				{Name: "dup", Value: "a", Inject: injectSpec{Env: "A"}},
				{Name: "dup", Value: "b", Inject: injectSpec{Env: "B"}},
			}},
			wantSub: "duplicate secret name",
		},
		{
			name:    "neither value nor valueFrom",
			spec:    fileSpec{Secrets: []secretSpec{{Name: "x", Inject: injectSpec{Env: "X"}}}},
			wantSub: "must set exactly one of",
		},
		{
			name: "both value and valueFrom",
			spec: fileSpec{Secrets: []secretSpec{{
				Name: "x", Value: "v",
				ValueFrom: &valueFromSpec{Env: "Y"},
				Inject:    injectSpec{Env: "X"},
			}}},
			wantSub: "mutually exclusive",
		},
		{
			name: "valueFrom without env field",
			spec: fileSpec{Secrets: []secretSpec{{
				Name:      "x",
				ValueFrom: &valueFromSpec{},
				Inject:    injectSpec{Env: "X"},
			}}},
			wantSub: "valueFrom",
		},
		{
			name: "invalid port string",
			spec: fileSpec{Secrets: []secretSpec{{
				Name: "x", Value: "v",
				Port: "not-a-port", Inject: injectSpec{Env: "X"},
			}}},
			wantSub: "invalid port",
		},
		{
			name: "missing inject targets",
			spec: fileSpec{Secrets: []secretSpec{{
				Name: "x", Value: "v",
			}}},
			wantSub: "at least one of `env` or `file`",
		},
		{
			name: "real value too long",
			spec: fileSpec{Secrets: []secretSpec{{
				Name: "x", Value: strings.Repeat("x", maxRealLen+1),
				Inject: injectSpec{Env: "X"},
			}}},
			wantSub: "max is 128",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := translate(tc.spec, newGen())
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}

func TestTranslate_HuffmanUnsatisfiableRejectsAtTranslateTime(t *testing.T) {
	// 'X' is one of HPACK's 8-bit codes; a 10-byte real of all-'X' has
	// no satisfiable shadow (the BPF wire-buffer invariant from PR #216).
	// The translator must surface this rather than ship a broken Source.
	spec := fileSpec{Secrets: []secretSpec{{
		Name:   "x10",
		Value:  strings.Repeat("X", 10),
		Inject: injectSpec{Env: "X10"},
	}}}
	_, err := translate(spec, newGen())
	if err == nil {
		t.Fatal("expected ErrHuffmanInvariantUnsatisfiable, got nil")
	}
	if !errors.Is(err, secrets.ErrHuffmanInvariantUnsatisfiable) {
		t.Errorf("expected errors.Is(_, ErrHuffmanInvariantUnsatisfiable); got: %v", err)
	}
}

func TestTranslate_BothInjectTargets(t *testing.T) {
	// env + file in the same entry is allowed; runtime exposes both.
	spec := fileSpec{Secrets: []secretSpec{{
		Name: "dual", Value: "abc-real-dual-1",
		Inject: injectSpec{Env: "DUAL", File: "/run/kloak/dual"},
	}}}
	out, err := translate(spec, newGen())
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if out[0].Inject.Env != "DUAL" || out[0].Inject.File != "/run/kloak/dual" {
		t.Errorf("Inject=%+v, want both Env and File set", out[0].Inject)
	}
}

func TestTranslate_PortWithProtocol(t *testing.T) {
	spec := fileSpec{Secrets: []secretSpec{{
		Name: "dns", Value: "TEST-fixture-12",
		Port: "53/udp", Inject: injectSpec{Env: "DNS"},
	}}}
	out, err := translate(spec, newGen())
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if out[0].Port != 53 || out[0].Protocol != uint8(unix.IPPROTO_UDP) {
		t.Errorf("Port=%d Protocol=%d, want 53/udp", out[0].Port, out[0].Protocol)
	}
}
