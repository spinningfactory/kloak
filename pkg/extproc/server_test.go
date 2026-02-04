package extproc

import (
	"context"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"

	"github.com/dhia/bouncer/pkg/storage"
)

func TestHandleRequestHeaders(t *testing.T) {
	store := storage.NewMemory()
	ctx := context.Background()

	// Store a hash mapping
	hash := "bouncer:abc123def456"
	originalValue := "sk-secret-api-key-12345"
	_ = store.Store(ctx, "test-pod", hash, originalValue)

	server := NewServer(store, logr.Discard())

	// Create request headers with hashed value
	headers := &extprocv3.HttpHeaders{
		Headers: &corev3.HeaderMap{
			Headers: []*corev3.HeaderValue{
				{Key: "authorization", Value: hash},
				{Key: "content-type", Value: "application/json"},
			},
		},
	}

	resp, err := server.handleRequestHeaders(ctx, headers)
	if err != nil {
		t.Fatalf("handleRequestHeaders failed: %v", err)
	}

	// Check response
	reqHeaders := resp.GetRequestHeaders()
	if reqHeaders == nil {
		t.Fatal("Expected request headers response")
	}

	if reqHeaders.Response.Status != extprocv3.CommonResponse_CONTINUE {
		t.Errorf("Expected CONTINUE status, got %v", reqHeaders.Response.Status)
	}

	// Check mutation
	mutation := reqHeaders.Response.HeaderMutation
	if mutation == nil {
		t.Fatal("Expected header mutation")
	}

	if len(mutation.SetHeaders) != 1 {
		t.Errorf("Expected 1 header mutation, got %d", len(mutation.SetHeaders))
	}

	if string(mutation.SetHeaders[0].Header.RawValue) != originalValue {
		t.Errorf("Expected rewritten value '%s', got '%s'",
			originalValue, string(mutation.SetHeaders[0].Header.RawValue))
	}
}

func TestHandleRequestHeaders_NoHash(t *testing.T) {
	store := storage.NewMemory()
	ctx := context.Background()
	server := NewServer(store, logr.Discard())

	// Create request headers without hashed values
	headers := &extprocv3.HttpHeaders{
		Headers: &corev3.HeaderMap{
			Headers: []*corev3.HeaderValue{
				{Key: "authorization", Value: "Bearer normal-token"},
				{Key: "content-type", Value: "application/json"},
			},
		},
	}

	resp, err := server.handleRequestHeaders(ctx, headers)
	if err != nil {
		t.Fatalf("handleRequestHeaders failed: %v", err)
	}

	reqHeaders := resp.GetRequestHeaders()
	if reqHeaders == nil {
		t.Fatal("Expected request headers response")
	}

	// Should have no mutations since no hashes
	if reqHeaders.Response.HeaderMutation != nil {
		t.Error("Expected no header mutations for non-hashed values")
	}
}
