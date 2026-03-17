package webhook

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeClient(objs ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = admissionregistrationv1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func TestEnsureWebhookCerts_CreatesNewSecret(t *testing.T) {
	c := newFakeClient()
	ctx := context.Background()

	certPEM, err := EnsureWebhookCerts(ctx, c, "kloak-system")
	if err != nil {
		t.Fatalf("EnsureWebhookCerts failed: %v", err)
	}

	if len(certPEM) == 0 {
		t.Fatal("certPEM is empty")
	}

	// Verify it's valid PEM
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	if cert.Subject.CommonName != "kloak-webhook.kloak-system.svc" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}

	// Verify DNS names
	expectedDNS := []string{
		"kloak-webhook",
		"kloak-webhook.kloak-system",
		"kloak-webhook.kloak-system.svc",
	}
	for i, dns := range expectedDNS {
		if i >= len(cert.DNSNames) || cert.DNSNames[i] != dns {
			t.Errorf("expected DNS name %q, got %v", dns, cert.DNSNames)
			break
		}
	}

	// Verify secret was created in cluster
	secret := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{Name: SecretName, Namespace: "kloak-system"}, secret); err != nil {
		t.Fatalf("secret not created: %v", err)
	}

	if _, ok := secret.Data[CertKey]; !ok {
		t.Error("secret missing tls.crt")
	}
	if _, ok := secret.Data[KeyKey]; !ok {
		t.Error("secret missing tls.key")
	}
}

func TestEnsureWebhookCerts_ReturnsExisting(t *testing.T) {
	existingCert := []byte("existing-cert-data")
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SecretName,
			Namespace: "kloak-system",
		},
		Data: map[string][]byte{
			CertKey: existingCert,
			KeyKey:  []byte("existing-key"),
		},
	}

	c := newFakeClient(existingSecret)
	ctx := context.Background()

	certPEM, err := EnsureWebhookCerts(ctx, c, "kloak-system")
	if err != nil {
		t.Fatalf("EnsureWebhookCerts failed: %v", err)
	}

	if string(certPEM) != "existing-cert-data" {
		t.Errorf("expected existing cert, got %q", certPEM)
	}
}

func TestEnsureWebhookCerts_ExistingSecretMissingCert(t *testing.T) {
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SecretName,
			Namespace: "kloak-system",
		},
		Data: map[string][]byte{
			KeyKey: []byte("key-only"),
		},
	}

	c := newFakeClient(existingSecret)
	ctx := context.Background()

	_, err := EnsureWebhookCerts(ctx, c, "kloak-system")
	if err == nil {
		t.Fatal("expected error for missing cert key")
	}
}

func TestEnsureWebhookCerts_PatchesWebhookConfig(t *testing.T) {
	webhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kloak-mutating-webhook",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name:         "pod.mutate.getkloak.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{},
			},
		},
	}

	c := newFakeClient(webhookConfig)
	ctx := context.Background()

	certPEM, err := EnsureWebhookCerts(ctx, c, "kloak-system")
	if err != nil {
		t.Fatalf("EnsureWebhookCerts failed: %v", err)
	}

	// Verify webhook config was patched
	updated := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := c.Get(ctx, client.ObjectKey{Name: "kloak-mutating-webhook"}, updated); err != nil {
		t.Fatal(err)
	}

	if len(updated.Webhooks[0].ClientConfig.CABundle) == 0 {
		t.Error("CABundle not patched")
	}
	if string(updated.Webhooks[0].ClientConfig.CABundle) != string(certPEM) {
		t.Error("CABundle doesn't match generated cert")
	}
}

func TestEnsureWebhookCerts_DifferentNamespace(t *testing.T) {
	c := newFakeClient()
	ctx := context.Background()

	certPEM, err := EnsureWebhookCerts(ctx, c, "custom-ns")
	if err != nil {
		t.Fatalf("EnsureWebhookCerts failed: %v", err)
	}

	// Verify cert has correct namespace in CN
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if cert.Subject.CommonName != "kloak-webhook.custom-ns.svc" {
		t.Errorf("expected CN for custom-ns, got %q", cert.Subject.CommonName)
	}

	// Verify secret in correct namespace
	secret := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{Name: SecretName, Namespace: "custom-ns"}, secret); err != nil {
		t.Fatalf("secret should be in custom-ns: %v", err)
	}
}

func TestPatchWebhookConfiguration_NotFound(t *testing.T) {
	c := newFakeClient() // no webhook config
	ctx := context.Background()

	// Should not error when webhook config doesn't exist
	err := patchWebhookConfiguration(ctx, c, []byte("cert-data"))
	if err != nil {
		t.Fatalf("should not error when webhook config is not found: %v", err)
	}
}

func TestPatchWebhookConfiguration_NoMatchingWebhook(t *testing.T) {
	webhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "kloak-mutating-webhook"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name:         "other.webhook.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{},
			},
		},
	}

	c := newFakeClient(webhookConfig)
	ctx := context.Background()

	err := patchWebhookConfiguration(ctx, c, []byte("cert-data"))
	if err != nil {
		t.Fatalf("should not error for non-matching webhook: %v", err)
	}

	// Verify CABundle was NOT set
	updated := &admissionregistrationv1.MutatingWebhookConfiguration{}
	_ = c.Get(ctx, client.ObjectKey{Name: "kloak-mutating-webhook"}, updated)
	if len(updated.Webhooks[0].ClientConfig.CABundle) != 0 {
		t.Error("CABundle should not be set for non-matching webhook name")
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSignedCert("test-ns")
	if err != nil {
		t.Fatalf("generateSelfSignedCert failed: %v", err)
	}

	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("empty cert or key")
	}

	// Verify cert
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("invalid cert PEM")
	}

	// Verify key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("invalid key PEM")
	}
}
