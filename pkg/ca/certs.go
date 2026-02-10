// Package certs provides certificate generation utilities for Kloak.
package ca

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	admissionv1 "k8s.io/api/admissionregistration/v1"
)

const (
	// CASecretName is the name of the CA secret
	CASecretName = "kloak-ca"
	// WebhookSecretName is the name of the webhook TLS secret
	WebhookSecretName = "kloak-webhook-certs"
	// WebhookConfigName is the name of the MutatingWebhookConfiguration
	WebhookConfigName = "kloak-mutating-webhook"
)

// generateWebhookCert creates a webhook TLS certificate signed by the CA
func generateWebhookCert(caCert, caKey []byte, namespace string) ([]byte, []byte, error) {
	// Load CA
	rootCA, err := LoadCA(caCert, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load CA: %w", err)
	}

	dnsNames := []string{
		"kloak-webhook",
		fmt.Sprintf("kloak-webhook.%s", namespace),
		fmt.Sprintf("kloak-webhook.%s.svc", namespace),
		fmt.Sprintf("kloak-webhook.%s.svc.cluster.local", namespace),
		"localhost",
	}

	// 1 year validity for webhook cert
	return rootCA.GenerateServerCert(dnsNames, 365*24*time.Hour)
}

// EnsureCerts ensures CA and webhook certificates exist, creating them if needed.
// Returns the CA cert PEM for use in webhook configuration.
func EnsureCerts(ctx context.Context, c client.Client, namespace string, log logr.Logger) ([]byte, error) {
	var caCert, caKey []byte

	// Check if CA secret exists
	caSecret := &corev1.Secret{}
	err := c.Get(ctx, types.NamespacedName{Name: CASecretName, Namespace: namespace}, caSecret)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get CA secret: %w", err)
		}

		// Generate new CA
		log.Info("Generating new CA certificate")
		rootCA, err := GenerateCA("Kloak Root CA", 10*365*24*time.Hour)
		if err != nil {
			return nil, err
		}
		caCert = rootCA.CertPEM
		caKey = rootCA.KeyPEM

		// Create CA secret
		caSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      CASecretName,
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":      "kloak",
					"app.kubernetes.io/component": "ca",
				},
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				corev1.TLSCertKey:       caCert,
				corev1.TLSPrivateKeyKey: caKey,
			},
		}
		if err := c.Create(ctx, caSecret); err != nil {
			return nil, fmt.Errorf("failed to create CA secret: %w", err)
		}
		log.Info("Created CA secret", "name", CASecretName)
	} else {
		log.Info("CA secret already exists", "name", CASecretName)
		caCert = caSecret.Data[corev1.TLSCertKey]
		caKey = caSecret.Data[corev1.TLSPrivateKeyKey]
	}

	// Check if webhook secret exists
	webhookSecret := &corev1.Secret{}
	err = c.Get(ctx, types.NamespacedName{Name: WebhookSecretName, Namespace: namespace}, webhookSecret)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get webhook secret: %w", err)
		}

		// Generate webhook cert signed by CA
		log.Info("Generating webhook certificate")
		log.Info("Generating webhook certificate")
		certPEM, keyPEM, err := generateWebhookCert(caCert, caKey, namespace)
		if err != nil {
			return nil, err
		}

		// Create webhook secret
		webhookSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      WebhookSecretName,
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":      "kloak",
					"app.kubernetes.io/component": "webhook",
				},
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				corev1.TLSCertKey:       certPEM,
				corev1.TLSPrivateKeyKey: keyPEM,
			},
		}
		if err := c.Create(ctx, webhookSecret); err != nil {
			return nil, fmt.Errorf("failed to create webhook secret: %w", err)
		}
		log.Info("Created webhook secret", "name", WebhookSecretName)
	} else {
		log.Info("Webhook secret already exists", "name", WebhookSecretName)
	}

	// Patch MutatingWebhookConfiguration with CA bundle
	if err := patchWebhookCABundle(ctx, c, caCert, log); err != nil {
		return nil, err
	}

	return caCert, nil
}

// patchWebhookCABundle updates the MutatingWebhookConfiguration with the CA bundle
func patchWebhookCABundle(ctx context.Context, c client.Client, caCert []byte, log logr.Logger) error {
	webhookConfig := &admissionv1.MutatingWebhookConfiguration{}
	err := c.Get(ctx, types.NamespacedName{Name: WebhookConfigName}, webhookConfig)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("MutatingWebhookConfiguration not found, skipping CA bundle patch", "name", WebhookConfigName)
			return nil
		}
		return fmt.Errorf("failed to get webhook configuration: %w", err)
	}

	// Update CA bundle for all webhooks
	caBundle := base64.StdEncoding.EncodeToString(caCert)
	needsUpdate := false
	for i := range webhookConfig.Webhooks {
		if string(webhookConfig.Webhooks[i].ClientConfig.CABundle) != string(caCert) {
			webhookConfig.Webhooks[i].ClientConfig.CABundle = []byte(caBundle)
			needsUpdate = true
		}
	}

	if needsUpdate {
		// Use raw bytes, not base64 encoded
		for i := range webhookConfig.Webhooks {
			webhookConfig.Webhooks[i].ClientConfig.CABundle = caCert
		}
		if err := c.Update(ctx, webhookConfig); err != nil {
			return fmt.Errorf("failed to update webhook configuration: %w", err)
		}
		log.Info("Updated MutatingWebhookConfiguration with CA bundle", "name", WebhookConfigName)
	}

	return nil
}
