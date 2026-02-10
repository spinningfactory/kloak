package ca

import (
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA("Kloak Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Verify certificate properties
	if ca.Cert.Subject.CommonName != "Kloak Test CA" {
		t.Errorf("Expected CN 'Kloak Test CA', got '%s'", ca.Cert.Subject.CommonName)
	}

	if !ca.Cert.IsCA {
		t.Error("Certificate should be a CA")
	}

	if len(ca.CertPEM) == 0 {
		t.Error("CertPEM should not be empty")
	}

	if len(ca.KeyPEM) == 0 {
		t.Error("KeyPEM should not be empty")
	}
}

func TestGenerateServerCert(t *testing.T) {
	ca, err := GenerateCA("Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	serverCert, serverKey, err := ca.GenerateServerCert([]string{"example.com"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateServerCert failed: %v", err)
	}

	if len(serverCert) == 0 {
		t.Error("Server certPEM should not be empty")
	}

	if len(serverKey) == 0 {
		t.Error("Server keyPEM should not be empty")
	}
}

func TestLoadCA(t *testing.T) {
	// Generate a CA
	original, err := GenerateCA("Load Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Load it back
	loaded, err := LoadCA(original.CertPEM, original.KeyPEM)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	// Verify it matches
	if loaded.Cert.Subject.CommonName != original.Cert.Subject.CommonName {
		t.Error("Loaded CA CN doesn't match original")
	}

	// Verify we can sign certs with loaded CA
	_, _, err = loaded.GenerateServerCert([]string{"test.com"}, time.Hour)
	if err != nil {
		t.Fatalf("Failed to sign with loaded CA: %v", err)
	}
}
