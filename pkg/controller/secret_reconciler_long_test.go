package controller

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// longValue returns n bytes of a token-like value (alphanumerics, about 6
// HPACK Huffman bits a byte): shadowable at any length. seed varies it.
func longValue(n int, seed uint64) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r := mrand.New(mrand.NewPCG(seed, uint64(n)))
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.IntN(len(chars))]
	}
	return string(b)
}

// sameLenOtherHuffman returns a value of v's length whose Huffman bit
// length differs (#269): v with its first bytes made 'e' (5 bits) or 'Z'
// (8 bits).
func sameLenOtherHuffman(v string) string {
	b := []byte(v)
	c := byte('Z')
	if secrets.HuffmanBits(v) > 6*len(v) {
		c = 'e'
	}
	for i := 0; i < len(b) && i < 64; i++ {
		b[i] = c
	}
	return string(b)
}

func enabledLongSecret(name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default", UID: types.UID(name + "-uid"),
			Labels: map[string]string{AnnotationSecretEnabled: "true"},
		},
		Data: data,
	}
}

func reconcileSecret(t *testing.T, r *SecretReconciler, name string) {
	t.Helper()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: "default"}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile %s: %v", name, err)
	}
}

func getShadow(t *testing.T, c client.Client, name string) *corev1.Secret {
	t.Helper()
	shadow := &corev1.Secret{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: name + ShadowSecretSuffix, Namespace: "default"}, shadow); err != nil {
		t.Fatalf("shadow of %s: %v", name, err)
	}
	return shadow
}

// TestSecretReconciler_LongValues checks shadows of values longer than the
// data plane takes today, with the maximum raised (a test stands for a data
// plane that takes them: the reconciler is given the effective maximum):
// whole, bit-exact, kept while the value stays, and minted again on a
// rotation to a same-length value of another Huffman bit length (#269).
func TestSecretReconciler_LongValues(t *testing.T) {
	for _, n := range []int{secrets.DataPlaneMaxLen + 1, 4 << 10, 64 << 10, secrets.MaxLenLimit} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			v := longValue(n, 1)
			secret := enabledLongSecret("long", map[string][]byte{"token": []byte(v)})
			r, c := newSecretReconciler(secret)
			rec := events.NewFakeRecorder(10)
			r.MaxSecretLen, r.Recorder = secrets.MaxLenLimit, rec

			reconcileSecret(t, r, "long")
			shadow := getShadow(t, c, "long")
			first := string(shadow.Data["token"])
			if len(first) != n || !strings.HasPrefix(first, secrets.ValuePrefix) ||
				secrets.HuffmanBits(first) != secrets.HuffmanBits(v) {
				t.Fatalf("shadow: %d bytes, %d Huffman bits; want %d, %d", len(first), secrets.HuffmanBits(first), n, secrets.HuffmanBits(v))
			}

			// Unchanged: kept, and not written again.
			version := shadow.ResourceVersion
			reconcileSecret(t, r, "long")
			if s := getShadow(t, c, "long"); string(s.Data["token"]) != first || s.ResourceVersion != version {
				t.Errorf("an unchanged secret's shadow was rewritten (version %s -> %s)", version, s.ResourceVersion)
			}

			// A rotation of the same length but another Huffman bit length.
			v2 := sameLenOtherHuffman(v)
			if secrets.HuffmanBits(v2) == secrets.HuffmanBits(v) {
				t.Fatal("fixture: same Huffman bits")
			}
			secret = &corev1.Secret{}
			if err := c.Get(context.Background(), types.NamespacedName{Name: "long", Namespace: "default"}, secret); err != nil {
				t.Fatal(err)
			}
			secret.Data["token"] = []byte(v2)
			if err := c.Update(context.Background(), secret); err != nil {
				t.Fatal(err)
			}
			reconcileSecret(t, r, "long")
			second := string(getShadow(t, c, "long").Data["token"])
			if second == first || len(second) != n || secrets.HuffmanBits(second) != secrets.HuffmanBits(v2) {
				t.Errorf("after the rotation: %d bytes, %d Huffman bits (reused: %v); want %d, %d",
					len(second), secrets.HuffmanBits(second), second == first, n, secrets.HuffmanBits(v2))
			}
			if len(rec.Events) != 0 {
				t.Errorf("events for shadowable keys: %v", <-rec.Events)
			}
		})
	}
}

// TestSecretReconciler_OverLimit checks a value longer than the maximum
// (the data plane's today): left out of the shadow, never truncated, the
// Secret's other keys still shadowed, and a Warning event that says why,
// without the value, once.
func TestSecretReconciler_OverLimit(t *testing.T) {
	long := longValue(secrets.DataPlaneMaxLen+1, 2)
	secret := enabledLongSecret("mixed", map[string][]byte{
		"long": []byte(long),
		"ok":   []byte(longValue(64, 3)),
	})
	r, c := newSecretReconciler(secret)
	rec := events.NewFakeRecorder(10)
	r.Recorder = rec // the default maximum: the data plane's

	reconcileSecret(t, r, "mixed")
	shadow := getShadow(t, c, "mixed")
	if _, ok := shadow.Data["long"]; ok || len(shadow.Data["ok"]) != 64 {
		t.Fatalf("shadow keys %v, want only ok", keysOf(shadow.Data))
	}
	if len(rec.Events) != 1 {
		t.Fatalf("%d events, want 1", len(rec.Events))
	}
	ev := <-rec.Events
	for _, want := range []string{corev1.EventTypeWarning, EventReasonKeysNotShadowed, "long", fmt.Sprintf("maximum %d", secrets.DataPlaneMaxLen)} {
		if !strings.Contains(ev, want) {
			t.Errorf("event %q does not say %q", ev, want)
		}
	}
	if strings.Contains(ev, long[:16]) {
		t.Errorf("event %q holds the value", ev)
	}

	// Another controller's reconcile (every node runs one) finds the shadow
	// up to date: no write, no second event.
	reconcileSecret(t, r, "mixed")
	if len(rec.Events) != 0 {
		t.Errorf("a second event: %v", <-rec.Events)
	}

	// Raised enough, the key is shadowed whole.
	r.MaxSecretLen = secrets.MaxLenLimit
	reconcileSecret(t, r, "mixed")
	if got := getShadow(t, c, "mixed").Data["long"]; len(got) != len(long) {
		t.Errorf("with the maximum raised: %d bytes, want %d", len(got), len(long))
	}

	// A Secret whose only key is over the limit gets no shadow, and the
	// event says so.
	only := enabledLongSecret("only-long", map[string][]byte{"long": []byte(long)})
	if err := c.Create(context.Background(), only); err != nil {
		t.Fatal(err)
	}
	r.MaxSecretLen = 0
	reconcileSecret(t, r, "only-long")
	if err := c.Get(context.Background(), types.NamespacedName{Name: "only-long" + ShadowSecretSuffix, Namespace: "default"}, &corev1.Secret{}); err == nil {
		t.Error("a shadow for a Secret with no shadowable key")
	}
	if len(rec.Events) != 1 || !strings.Contains(<-rec.Events, "no shadow secret is created") {
		t.Error("no event for a Secret with no shadowable key")
	}
}
