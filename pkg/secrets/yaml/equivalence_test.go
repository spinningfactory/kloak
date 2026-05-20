package yaml

import (
	"context"
	"testing"

	"golang.org/x/net/http2/hpack"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/spinningfactory/kloak/pkg/secrets"
	k8ssrc "github.com/spinningfactory/kloak/pkg/secrets/k8s"
)

// TestEquivalence_YAMLvsK8s proves that the YAML adapter and the k8s
// adapter produce semantically identical secrets — same Real, Host,
// Port, Protocol — when fed equivalent inputs. This is the contract
// that lets `kloak run` reuse every byte of the data plane.
//
// Fields excluded from the comparison:
//   - Shadow:  random per generator
//   - OwnerID: format-specific identifier (namespace/name vs name);
//     internal to collision tracking, not visible to BPF.
//   - Inject:  YAML-only; k8s adapter leaves it zero. Verified by
//     other tests in this package.
//   - IP:      not exercised here; covered by TestTranslate_HostParsedAsLiteralIP.
func TestEquivalence_YAMLvsK8s(t *testing.T) {
	const (
		realValue = "sk-live-equivalence-test"
		host      = "api.stripe.com"
		port      = "443"
	)

	// --- k8s side: build a fake client with an enabled + shadow Secret.
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	enabled := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "stripe-key",
			Namespace: "default",
			Labels:    map[string]string{k8ssrc.LabelEnabled: "true"},
			Annotations: map[string]string{
				k8ssrc.AnnotationHosts: host,
				k8ssrc.AnnotationPort:  port,
			},
		},
		Data: map[string][]byte{"api-key": []byte(realValue)},
	}
	// Mint a shadow up-front so the k8s join sees one.
	gen := secrets.NewShadowGenerator(nil, nil)
	shadowVal, err := gen.Generate(len(realValue), int(hpack.HuffmanEncodeLength(realValue)), "default/stripe-key", 20)
	if err != nil {
		t.Fatalf("shadow gen: %v", err)
	}
	shadow := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "stripe-key-kloak",
			Namespace: "default",
			Labels: map[string]string{
				k8ssrc.LabelManaged: "true",
				k8ssrc.LabelOwner:   "stripe-key",
			},
		},
		Data: map[string][]byte{"api-key": []byte(shadowVal)},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabled, shadow).Build()
	k8sSrc := k8ssrc.NewSource(cl)
	k8sSnap, err := k8sSrc.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("k8s Snapshot: %v", err)
	}
	if len(k8sSnap) != 1 {
		t.Fatalf("k8s snapshot len=%d, want 1", len(k8sSnap))
	}

	// --- yaml side: equivalent entry through the YAML translator.
	path := writeTempYAML(t, `secrets:
  - name: stripe-key
    value: sk-live-equivalence-test
    host: api.stripe.com
    port: 443
    inject:
      env: STRIPE_KEY
`)
	ySrc, err := NewSource(path)
	if err != nil {
		t.Fatalf("yaml NewSource: %v", err)
	}
	ySnap, err := ySrc.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("yaml Snapshot: %v", err)
	}
	if len(ySnap) != 1 {
		t.Fatalf("yaml snapshot len=%d, want 1", len(ySnap))
	}

	k, y := k8sSnap[0], ySnap[0]
	if k.Real != y.Real {
		t.Errorf("Real mismatch: k8s=%q yaml=%q", k.Real, y.Real)
	}
	if k.Host != y.Host {
		t.Errorf("Host mismatch: k8s=%q yaml=%q", k.Host, y.Host)
	}
	if k.Port != y.Port {
		t.Errorf("Port mismatch: k8s=%d yaml=%d", k.Port, y.Port)
	}
	if k.Protocol != y.Protocol {
		t.Errorf("Protocol mismatch: k8s=%d yaml=%d", k.Protocol, y.Protocol)
	}
	// Sanity: YAML side populates Inject; k8s side doesn't.
	if y.Inject.Env != "STRIPE_KEY" {
		t.Errorf("yaml Inject.Env=%q, want STRIPE_KEY", y.Inject.Env)
	}
	if k.Inject != (secrets.Inject{}) {
		t.Errorf("k8s Inject should be zero, got %+v", k.Inject)
	}
}
