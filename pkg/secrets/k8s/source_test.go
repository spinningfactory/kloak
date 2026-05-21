package k8s

import (
	"context"
	"net"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	return s
}

// makeEnabled builds an enabled (real) Secret with the given annotations.
func makeEnabled(ns, name string, data map[string]string, ann map[string]string) *corev1.Secret {
	d := make(map[string][]byte, len(data))
	for k, v := range data {
		d[k] = []byte(v)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Labels:      map[string]string{LabelEnabled: "true"},
			Annotations: ann,
		},
		Data: d,
	}
}

// makeShadow builds the corresponding kloak-managed shadow Secret.
func makeShadow(ns, ownerName string, data map[string]string) *corev1.Secret {
	d := make(map[string][]byte, len(data))
	for k, v := range data {
		d[k] = []byte(v)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ownerName + ShadowSecretSuffix,
			Namespace: ns,
			Labels: map[string]string{
				LabelManaged: "true",
				LabelOwner:   ownerName,
			},
		},
		Data: d,
	}
}

func TestSnapshot_NilReader(t *testing.T) {
	s := NewSource(nil)
	got, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil reader: got %d entries, want 0", len(got))
	}
}

func TestSnapshot_JoinsEnabledAndShadow(t *testing.T) {
	scheme := newScheme(t)
	enabled := makeEnabled("default", "stripe", map[string]string{
		"api-key": "sk-live-real-12345678",
	}, map[string]string{
		AnnotationHosts: "api.stripe.com",
		AnnotationPort:  "443/tcp",
	})
	shadow := makeShadow("default", "stripe", map[string]string{
		"api-key": "kl::0123456789abcdefABCDEFGHJK",
	})
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(enabled, shadow).
		Build()

	got, err := NewSource(c).Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(got), got)
	}
	s := got[0]
	if s.OwnerID != "default/stripe" {
		t.Errorf("OwnerID=%q want default/stripe", s.OwnerID)
	}
	if s.Key != "api-key" {
		t.Errorf("Key=%q want api-key", s.Key)
	}
	if s.Real != "sk-live-real-12345678" {
		t.Errorf("Real=%q", s.Real)
	}
	if s.Shadow != "kl::0123456789abcdefABCDEFGHJK" {
		t.Errorf("Shadow=%q", s.Shadow)
	}
	if s.Host != "api.stripe.com" {
		t.Errorf("Host=%q want api.stripe.com", s.Host)
	}
	if s.IP != nil {
		t.Errorf("IP=%v want nil for hostname filter", s.IP)
	}
	if s.Port != 443 {
		t.Errorf("Port=%d want 443", s.Port)
	}
	if s.Protocol == 0 {
		t.Errorf("Protocol=0 want IPPROTO_TCP")
	}
}

func TestSnapshot_LiteralIPHost(t *testing.T) {
	scheme := newScheme(t)
	enabled := makeEnabled("ns1", "echo", map[string]string{
		"k": "real-value-1234",
	}, map[string]string{
		AnnotationHosts: "10.0.0.42",
	})
	shadow := makeShadow("ns1", "echo", map[string]string{
		"k": "kl::01234567",
	})
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabled, shadow).Build()

	got, _ := NewSource(c).Snapshot(context.Background())
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Host != "" {
		t.Errorf("Host=%q want empty (IP-mode)", got[0].Host)
	}
	if !got[0].IP.Equal(net.ParseIP("10.0.0.42")) {
		t.Errorf("IP=%v want 10.0.0.42", got[0].IP)
	}
}

func TestSnapshot_SkipsMissingShadow(t *testing.T) {
	scheme := newScheme(t)
	// Enabled secret with no matching shadow.
	enabled := makeEnabled("default", "orphan", map[string]string{
		"k": "v-12345678",
	}, nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabled).Build()

	got, err := NewSource(c).Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("orphan should be skipped, got %d entries", len(got))
	}
}

func TestSnapshot_SkipsTooShortShadow(t *testing.T) {
	scheme := newScheme(t)
	enabled := makeEnabled("default", "owner", map[string]string{"k": "long-enough-real"}, nil)
	shadow := makeShadow("default", "owner", map[string]string{"k": "short"}) // < ShadowPrefixLen
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabled, shadow).Build()

	got, _ := NewSource(c).Snapshot(context.Background())
	if len(got) != 0 {
		t.Errorf("too-short shadow should be skipped, got %d entries", len(got))
	}
}

func TestSnapshot_MultipleDataKeys(t *testing.T) {
	scheme := newScheme(t)
	enabled := makeEnabled("default", "multi", map[string]string{
		"a": "real-a-1234",
		"b": "real-b-5678",
	}, nil)
	shadow := makeShadow("default", "multi", map[string]string{
		"a": "kl::aa01234567",
		"b": "kl::bb01234567",
	})
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabled, shadow).Build()

	got, _ := NewSource(c).Snapshot(context.Background())
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2", len(got))
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Key < got[j].Key })
	if got[0].Key != "a" || got[1].Key != "b" {
		t.Errorf("keys: %q, %q", got[0].Key, got[1].Key)
	}
	for _, s := range got {
		if s.OwnerID != "default/multi" {
			t.Errorf("entries should share OwnerID, got %q", s.OwnerID)
		}
	}
}

func TestSnapshot_BadPortAnnotationFallsBackToWildcard(t *testing.T) {
	scheme := newScheme(t)
	enabled := makeEnabled("default", "bad", map[string]string{"k": "real-val-1234"}, map[string]string{
		AnnotationPort: "garbage",
	})
	shadow := makeShadow("default", "bad", map[string]string{"k": "kl::0011223344"})
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabled, shadow).Build()

	got, _ := NewSource(c).Snapshot(context.Background())
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Port != 0 || got[0].Protocol != 0 {
		t.Errorf("bad port annotation should yield wildcard, got Port=%d Protocol=%d", got[0].Port, got[0].Protocol)
	}
}

func TestSeedShadowGenerator(t *testing.T) {
	scheme := newScheme(t)
	// Two managed shadows in different owners share a prefix; one's
	// data also has a too-short value that must be ignored.
	shadow1 := makeShadow("ns", "alice", map[string]string{"k": "kl::01ABCDEFGH"})
	shadow2 := makeShadow("ns", "bob", map[string]string{
		"k1":    "kl::01ABCDEFGH", // same prefix as alice
		"short": "tiny",           // skipped: < ShadowPrefixLen
	})
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(shadow1, shadow2).Build()

	seed, err := SeedShadowGenerator(context.Background(), c)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	prefix := "kl::01AB"
	owners := seed[prefix]
	if len(owners) != 2 {
		t.Errorf("prefix %q: got %d owners, want 2 (alice, bob)", prefix, len(owners))
	}
	if _, ok := owners["ns/alice"]; !ok {
		t.Errorf("missing ns/alice in owners for %q: %v", prefix, owners)
	}
	if _, ok := owners["ns/bob"]; !ok {
		t.Errorf("missing ns/bob in owners for %q: %v", prefix, owners)
	}
}

func TestSeedShadowGenerator_SkipsOwnerless(t *testing.T) {
	// A managed shadow without a getkloak.io/owner label is malformed
	// (kloak's reconciler always sets it). If we kept it, multiple
	// such shadows would alias under the phantom ownerID
	// "<namespace>/" and pollute the collision map. Skip them.
	scheme := newScheme(t)
	good := makeShadow("ns", "alice", map[string]string{"k": "kl::goodPRFX"})
	// Build an ownerless managed shadow by hand (makeShadow always
	// sets LabelOwner).
	ownerless := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "stranger-kloak",
			Namespace: "ns",
			Labels:    map[string]string{LabelManaged: "true"},
		},
		Data: map[string][]byte{"k": []byte("kl::badPRFXX")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(good, ownerless).Build()

	seed, err := SeedShadowGenerator(context.Background(), c)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	// alice's prefix should be present.
	if _, ok := seed["kl::good"]; !ok {
		t.Errorf("good owner's prefix missing from seed: %v", seed)
	}
	// The ownerless shadow's prefix must not be present.
	if owners, ok := seed["kl::badP"]; ok {
		t.Errorf("ownerless shadow leaked into seed under owners %v", owners)
	}
}

func TestSeedShadowGenerator_NilReader(t *testing.T) {
	seed, err := SeedShadowGenerator(context.Background(), nil)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(seed) != 0 {
		t.Errorf("nil reader: got %d prefixes, want 0", len(seed))
	}
}
