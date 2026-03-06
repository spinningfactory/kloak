package webhook

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	SecretName = "kloak-webhook-certs"
	CertKey    = "tls.crt"
	KeyKey     = "tls.key"
)

// EnsureWebhookCerts generates a self-signed certificate for the mutating webhook
// if the secret does not already exist in the cluster.
func EnsureWebhookCerts(ctx context.Context, c client.Client, namespace string) ([]byte, error) {
	// Check if secret already exists
	secret := &corev1.Secret{}
	err := c.Get(ctx, client.ObjectKey{Name: SecretName, Namespace: namespace}, secret)
	if err == nil {
		// Secret exists, return the cert
		if cert, ok := secret.Data[CertKey]; ok {
			return cert, nil
		}
		return nil, fmt.Errorf("secret %s exists but missing %s", SecretName, CertKey)
	}
	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get secret %s: %w", SecretName, err)
	}

	// Secret not found, generate new certs
	certPEM, keyPEM, err := generateSelfSignedCert(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certs: %w", err)
	}

	// Create the secret
	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SecretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			CertKey: certPEM,
			KeyKey:  keyPEM,
		},
	}

	if err := c.Create(ctx, newSecret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another controller created it in the meantime
			return EnsureWebhookCerts(ctx, c, namespace) // Retry getting it
		}
		return nil, fmt.Errorf("failed to create secret %s: %w", SecretName, err)
	}

	if err := patchWebhookConfiguration(ctx, c, certPEM); err != nil {
		return nil, fmt.Errorf("failed to patch webhook configuration: %w", err)
	}

	return certPEM, nil
}

func patchWebhookConfiguration(ctx context.Context, c client.Client, certPEM []byte) error {
	webhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{}
	err := c.Get(ctx, types.NamespacedName{Name: "kloak-mutating-webhook"}, webhookConfig)
	if err != nil {
		// If it doesn't exist yet, we can't patch it. The quick setup might apply it after the controller starts.
		// For now, return nil and let it be. But typically we should patch it.
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	patched := false
	for i, wh := range webhookConfig.Webhooks {
		if wh.Name == "pod.mutate.getkloak.io" {
			webhookConfig.Webhooks[i].ClientConfig.CABundle = certPEM
			patched = true
		}
	}

	if patched {
		if err := c.Update(ctx, webhookConfig); err != nil {
			return err
		}
	}
	return nil
}

func generateSelfSignedCert(namespace string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10 years

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("kloak-webhook.%s.svc", namespace),
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{
			"kloak-webhook",
			fmt.Sprintf("kloak-webhook.%s", namespace),
			fmt.Sprintf("kloak-webhook.%s.svc", namespace),
		},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	var certPEMBuf bytes.Buffer
	if err := pem.Encode(&certPEMBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, err
	}

	var keyPEMBuf bytes.Buffer
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	if err := pem.Encode(&keyPEMBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, err
	}

	return certPEMBuf.Bytes(), keyPEMBuf.Bytes(), nil
}
