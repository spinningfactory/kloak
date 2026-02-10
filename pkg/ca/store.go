package ca

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// SecretName is the name of the Kubernetes Secret storing the CA.
	SecretName = "kloak-ca"

	// CertKey is the key for the certificate in the Secret data.
	CertKey = "ca.crt"

	// KeyKey is the key for the private key in the Secret data.
	KeyKey = "ca.key"
)

// Store manages CA storage in Kubernetes Secrets.
type Store struct {
	client    client.Client
	namespace string
}

// NewStore creates a new CA store.
func NewStore(c client.Client, namespace string) *Store {
	return &Store{
		client:    c,
		namespace: namespace,
	}
}

// GetOrCreate retrieves the CA from Kubernetes, or creates a new one if it doesn't exist.
func (s *Store) GetOrCreate(ctx context.Context) (*CA, error) {
	secret := &corev1.Secret{}
	err := s.client.Get(ctx, client.ObjectKey{
		Namespace: s.namespace,
		Name:      SecretName,
	}, secret)

	secretFound := false
	var loadedCA *CA

	if err == nil {
		secretFound = true
		loadedCA, err = loadFromSecret(secret)
		if err == nil {
			return loadedCA, nil
		}
		// If loading failed (invalid data), we regenerate
	} else if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("getting secret: %w", err)
	}

	// Secret doesn't exist or is invalid, create new CA
	ca, err := GenerateCA("Kloak Root CA", DefaultValidDuration)
	if err != nil {
		return nil, fmt.Errorf("generating CA: %w", err)
	}

	// Create or Update secret
	secret.ObjectMeta = metav1.ObjectMeta{
		Name:      SecretName,
		Namespace: s.namespace,
		Labels: map[string]string{
			"app.kubernetes.io/name":      "kloak",
			"app.kubernetes.io/component": "ca",
		},
	}
	secret.Type = corev1.SecretTypeTLS
	secret.Data = map[string][]byte{
		CertKey:                 ca.CertPEM,
		KeyKey:                  ca.KeyPEM,
		corev1.TLSCertKey:       ca.CertPEM, // Also store as tls.crt for compatibility
		corev1.TLSPrivateKeyKey: ca.KeyPEM,  // Also store as tls.key
	}

	if secretFound {
		// Secret existed but was invalid, so we update it
		if err := s.client.Update(ctx, secret); err != nil {
			return nil, fmt.Errorf("updating secret: %w", err)
		}
	} else {
		// Secret didn't exist, create it
		if err := s.client.Create(ctx, secret); err != nil {
			return nil, fmt.Errorf("creating secret: %w", err)
		}
	}

	return ca, nil
}

// loadFromSecret attempts to load CA from a K8s secret, handling standard and legacy keys.
func loadFromSecret(secret *corev1.Secret) (*CA, error) {
	// First try tls.crt/tls.key (standard TLS secret format)
	certPEM, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		// Fallback to ca.crt/ca.key for backwards compatibility
		certPEM, ok = secret.Data[CertKey]
		if !ok {
			return nil, fmt.Errorf("secret missing %s or %s key", corev1.TLSCertKey, CertKey)
		}
	}
	keyPEM, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		keyPEM, ok = secret.Data[KeyKey]
		if !ok {
			return nil, fmt.Errorf("secret missing %s or %s key", corev1.TLSPrivateKeyKey, KeyKey)
		}
	}

	return LoadCA(certPEM, keyPEM)
}

// DefaultValidDuration is 10 years for the Root CA.
const DefaultValidDuration = 10 * 365 * 24 * 60 * 60 * 1e9 // 10 years in nanoseconds
