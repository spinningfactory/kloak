package sds

import (
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/spinningfactory/kloak/pkg/ca"
)

func TestGetOrCreateCert(t *testing.T) {
	// Create a test CA
	rootCA, err := ca.GenerateCA("Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	server := NewServer(rootCA, logr.Discard())

	// Generate cert for a domain
	secret, err := server.getOrCreateCert("example.com")
	if err != nil {
		t.Fatalf("Failed to get cert: %v", err)
	}

	if secret.Name != "example.com" {
		t.Errorf("Expected secret name 'example.com', got '%s'", secret.Name)
	}

	tlsCert := secret.GetTlsCertificate()
	if tlsCert == nil {
		t.Fatal("Expected TLS certificate in secret")
	}

	if len(tlsCert.CertificateChain.GetInlineBytes()) == 0 {
		t.Error("Certificate chain should not be empty")
	}

	if len(tlsCert.PrivateKey.GetInlineBytes()) == 0 {
		t.Error("Private key should not be empty")
	}

	// Verify caching
	if server.CacheSize() != 1 {
		t.Errorf("Expected cache size 1, got %d", server.CacheSize())
	}

	// Get same cert again (should be cached)
	secret2, err := server.getOrCreateCert("example.com")
	if err != nil {
		t.Fatalf("Failed to get cached cert: %v", err)
	}

	if secret != secret2 {
		t.Error("Expected cached cert to be returned")
	}

	// Cache size should still be 1
	if server.CacheSize() != 1 {
		t.Errorf("Expected cache size 1 after cache hit, got %d", server.CacheSize())
	}
}

func TestClearCache(t *testing.T) {
	rootCA, _ := ca.GenerateCA("Test CA", 24*time.Hour)
	server := NewServer(rootCA, logr.Discard())

	// Add some certs
	server.getOrCreateCert("a.com")
	server.getOrCreateCert("b.com")

	if server.CacheSize() != 2 {
		t.Errorf("Expected cache size 2, got %d", server.CacheSize())
	}

	// Clear cache
	server.ClearCache()

	if server.CacheSize() != 0 {
		t.Errorf("Expected cache size 0 after clear, got %d", server.CacheSize())
	}
}
