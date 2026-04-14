package controller

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/spinningfactory/kloak/pkg/storage"
)

func newSecretReconciler(objs ...client.Object) (*SecretReconciler, client.Client) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return &SecretReconciler{
		Client:  c,
		Log:     zap.NewNop().Sugar(),
		Scheme:  scheme,
		Storage: storage.NewMemory(),
	}, c
}

func TestSecretReconciler_CreatesShadowSecret(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
			Labels:    map[string]string{AnnotationSecretEnabled: "true"},
			UID:       "test-uid",
		},
		Data: map[string][]byte{
			"api-key": []byte("super-secret-value-12345678"),
		},
	}

	r, c := newSecretReconciler(secret)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "my-secret", Namespace: "default"}}

	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("unexpected requeue")
	}

	// Verify shadow secret was created
	shadow := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: "my-secret-kloak", Namespace: "default"}, shadow); err != nil {
		t.Fatalf("shadow secret not found: %v", err)
	}

	// Check labels
	if shadow.Labels["getkloak.io/managed"] != "true" {
		t.Error("shadow missing managed label")
	}
	if shadow.Labels["getkloak.io/owner"] != "my-secret" {
		t.Error("shadow missing owner label")
	}

	// Check OwnerReference
	if len(shadow.OwnerReferences) == 0 || shadow.OwnerReferences[0].Name != "my-secret" {
		t.Error("shadow missing OwnerReference")
	}

	// Check shadow data
	shadowVal, ok := shadow.Data["api-key"]
	if !ok {
		t.Fatal("shadow missing api-key")
	}
	if len(shadowVal) != len("super-secret-value-12345678") {
		t.Errorf("shadow length %d != original length %d", len(shadowVal), len("super-secret-value-12345678"))
	}
	if !strings.HasPrefix(string(shadowVal), ValuePrefix) {
		t.Errorf("shadow value %q should start with %q", shadowVal, ValuePrefix)
	}

	// Check storage has the mapping
	entries, err := r.Storage.List(ctx)
	if err != nil {
		t.Fatalf("storage list failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 storage entry, got %d", len(entries))
	}
	for _, entry := range entries {
		if entry.Value != "super-secret-value-12345678" {
			t.Errorf("storage value %q != original", entry.Value)
		}
	}
}

func TestSecretReconciler_DisabledSecretNoShadow(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "disabled-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{"key": []byte("value")},
	}

	r, c := newSecretReconciler(secret)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "disabled-secret", Namespace: "default"}}

	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	shadow := &corev1.Secret{}
	err = c.Get(ctx, types.NamespacedName{Name: "disabled-secret-kloak", Namespace: "default"}, shadow)
	if err == nil {
		t.Error("shadow should not exist for disabled secret")
	}
}

func TestSecretReconciler_DisableRemovesShadow(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "toggle-secret",
			Namespace: "default",
			Labels:    map[string]string{AnnotationSecretEnabled: "true"},
			UID:       "toggle-uid",
		},
		Data: map[string][]byte{"key": []byte("value-for-toggle-test!!")},
	}

	r, c := newSecretReconciler(secret)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "toggle-secret", Namespace: "default"}}

	// First reconcile — creates shadow
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}

	// Verify shadow exists
	shadow := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: "toggle-secret-kloak", Namespace: "default"}, shadow); err != nil {
		t.Fatalf("shadow not created: %v", err)
	}

	// Disable the secret
	if err := c.Get(ctx, types.NamespacedName{Name: "toggle-secret", Namespace: "default"}, secret); err != nil {
		t.Fatal(err)
	}
	delete(secret.Labels, AnnotationSecretEnabled)
	if err := c.Update(ctx, secret); err != nil {
		t.Fatal(err)
	}

	// Second reconcile — should delete shadow
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	err := c.Get(ctx, types.NamespacedName{Name: "toggle-secret-kloak", Namespace: "default"}, shadow)
	if err == nil {
		t.Error("shadow should be deleted after disabling")
	}
}

func TestSecretReconciler_UpdateShadow(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "stable-secret",
			Namespace: "default",
			Labels:    map[string]string{AnnotationSecretEnabled: "true"},
			UID:       "stable-uid",
		},
		Data: map[string][]byte{"key": []byte("original-value-same-length!!")},
	}

	r, c := newSecretReconciler(secret)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "stable-secret", Namespace: "default"}}

	// First reconcile — creates shadow
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	// Update original secret with different-length value
	if err := c.Get(ctx, types.NamespacedName{Name: "stable-secret", Namespace: "default"}, secret); err != nil {
		t.Fatal(err)
	}
	secret.Data["key"] = []byte("new-value-different-length-here!!!!!!")
	if err := c.Update(ctx, secret); err != nil {
		t.Fatal(err)
	}

	// Second reconcile — shadow should be updated with new length
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	shadow := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: "stable-secret-kloak", Namespace: "default"}, shadow); err != nil {
		t.Fatal(err)
	}

	if len(shadow.Data["key"]) != len("new-value-different-length-here!!!!!!") {
		t.Errorf("shadow length %d != new original length %d", len(shadow.Data["key"]), len("new-value-different-length-here!!!!!!"))
	}

	// Storage should have the new value
	entries, _ := r.Storage.List(ctx)
	found := false
	for _, entry := range entries {
		if entry.Value == "new-value-different-length-here!!!!!!" {
			found = true
		}
	}
	if !found {
		t.Error("storage should contain the updated value")
	}
}

func TestSecretReconciler_HostsLabel(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "host-secret",
			Namespace: "default",
			Labels: map[string]string{
				AnnotationSecretEnabled: "true",
				"getkloak.io/hosts":     "api.example.com, cdn.example.com",
			},
			UID: "host-uid",
		},
		Data: map[string][]byte{"token": []byte("host-restricted-secret-value!!")},
	}

	r, _ := newSecretReconciler(secret)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "host-secret", Namespace: "default"}}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	entries, _ := r.Storage.List(ctx)
	for _, entry := range entries {
		if len(entry.AllowedHosts) != 2 {
			t.Fatalf("expected 2 allowed hosts, got %d: %v", len(entry.AllowedHosts), entry.AllowedHosts)
		}
		if entry.AllowedHosts[0] != "api.example.com" || entry.AllowedHosts[1] != "cdn.example.com" {
			t.Errorf("unexpected hosts: %v", entry.AllowedHosts)
		}
	}
}

func TestSecretReconciler_MultipleKeys(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-key",
			Namespace: "default",
			Labels:    map[string]string{AnnotationSecretEnabled: "true"},
			UID:       "multi-uid",
		},
		Data: map[string][]byte{
			"username": []byte("admin-user-for-testing!!"),
			"password": []byte("super-secret-password!!!"),
			"token":    []byte("tok_live_abcdefghijklmnop"),
		},
	}

	r, c := newSecretReconciler(secret)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "multi-key", Namespace: "default"}}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	shadow := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: "multi-key-kloak", Namespace: "default"}, shadow); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"username", "password", "token"} {
		val, ok := shadow.Data[key]
		if !ok {
			t.Errorf("shadow missing key %q", key)
			continue
		}
		if len(val) != len(secret.Data[key]) {
			t.Errorf("key %q: shadow len %d != original len %d", key, len(val), len(secret.Data[key]))
		}
	}

	entries, _ := r.Storage.List(ctx)
	if len(entries) != 3 {
		t.Errorf("expected 3 storage entries, got %d", len(entries))
	}
}

func TestSecretReconciler_ShortSecret(t *testing.T) {
	// Test that secrets shorter than ShadowPrefixLen (8 bytes) are skipped
	// and no shadow secret is created
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "short-secret",
			Namespace: "default",
			Labels:    map[string]string{AnnotationSecretEnabled: "true"},
			UID:       "short-uid",
		},
		Data: map[string][]byte{"key": []byte("abc")}, // shorter than ShadowPrefixLen
	}

	r, c := newSecretReconciler(secret)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "short-secret", Namespace: "default"}}

	// Should not error, but should skip processing
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	// Shadow secret should not be created
	shadow := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: "short-secret-kloak", Namespace: "default"}, shadow); err == nil {
		t.Error("expected no shadow secret for short secret, but got one")
	} else if !errors.IsNotFound(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSecretReconciler_NotFoundSecret(t *testing.T) {
	r, _ := newSecretReconciler() // no objects
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "missing", Namespace: "default"}}

	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("reconcile should not error on NotFound: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("should not requeue for NotFound")
	}
}
