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
	SecretName = "bouncer-ca"

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

	if err == nil {
		secretFound = true
		// Secret exists, try to load CA
		certPEM, okCert := secret.Data[CertKey]
		keyPEM, okKey := secret.Data[KeyKey]

		if okCert && okKey {
			return LoadCA(certPEM, keyPEM)
		}

		// If keys are missing, we fall through to regenerate
		// But first, we need to delete the invalid secret or just update it?
		// Update is safer. We will overwrite the data.
	} else if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("getting secret: %w", err)
	}

	// Secret doesn't exist, create new CA
	ca, err := GenerateCA("Bouncer Root CA", DefaultValidDuration)
	if err != nil {
		return nil, fmt.Errorf("generating CA: %w", err)
	}

	// Create or Update secret
	secret.ObjectMeta = metav1.ObjectMeta{
		Name:      SecretName,
		Namespace: s.namespace,
		Labels: map[string]string{
			"app.kubernetes.io/name":      "bouncer",
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

// Get retrieves the CA from Kubernetes. Returns error if it doesn't exist.
func (s *Store) Get(ctx context.Context) (*CA, error) {
	secret := &corev1.Secret{}
	err := s.client.Get(ctx, client.ObjectKey{
		Namespace: s.namespace,
		Name:      SecretName,
	}, secret)
	if err != nil {
		return nil, fmt.Errorf("getting secret: %w", err)
	}

	certPEM, ok := secret.Data[CertKey]
	if !ok {
		return nil, fmt.Errorf("secret missing %s key", CertKey)
	}
	keyPEM, ok := secret.Data[KeyKey]
	if !ok {
		return nil, fmt.Errorf("secret missing %s key", KeyKey)
	}

	return LoadCA(certPEM, keyPEM)
}

// DefaultValidDuration is 10 years for the Root CA.
const DefaultValidDuration = 10 * 365 * 24 * 60 * 60 * 1e9 // 10 years in nanoseconds
