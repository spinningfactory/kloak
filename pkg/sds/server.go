// Package sds provides the Secret Discovery Service for dynamic certificate generation.
package sds

import (
	"context"
	"fmt"
	"sync"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/dhia/bouncer/pkg/ca"
)

// Server implements the xDS Secret Discovery Service for dynamic certs.
type Server struct {
	secret.UnimplementedSecretDiscoveryServiceServer

	ca        *ca.CA
	log       logr.Logger
	certCache map[string]*tls.Secret
	cacheMu   sync.RWMutex
	certTTL   time.Duration
}

// NewServer creates a new SDS server.
func NewServer(rootCA *ca.CA, log logr.Logger) *Server {
	return &Server{
		ca:        rootCA,
		log:       log,
		certCache: make(map[string]*tls.Secret),
		certTTL:   24 * time.Hour,
	}
}

// Register registers the SDS server with a gRPC server.
func (s *Server) Register(grpcServer *grpc.Server) {
	secret.RegisterSecretDiscoveryServiceServer(grpcServer, s)
}

// StreamSecrets implements the streaming xDS API.
func (s *Server) StreamSecrets(stream secret.SecretDiscoveryService_StreamSecretsServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		resp, err := s.handleRequest(stream.Context(), req)
		if err != nil {
			s.log.Error(err, "failed to handle SDS request")
			continue
		}

		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// FetchSecrets implements the unary xDS API.
func (s *Server) FetchSecrets(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	return s.handleRequest(ctx, req)
}

// DeltaSecrets implements the delta xDS API (not used).
func (s *Server) DeltaSecrets(stream secret.SecretDiscoveryService_DeltaSecretsServer) error {
	return fmt.Errorf("delta secrets not implemented")
}

// handleRequest processes an SDS request and returns certificates.
func (s *Server) handleRequest(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	var resources []*anypb.Any

	for _, resourceName := range req.ResourceNames {
		// resourceName is typically the SNI (domain name)
		domain := resourceName
		if domain == "" || domain == "bouncer-dynamic-cert" {
			// Default cert request - we'll use a placeholder
			domain = "httpbin.org"
		}

		secretPtr, err := s.getOrCreateCert(domain)
		if err != nil {
			return nil, fmt.Errorf("generating cert for %s: %w", domain, err)
		}

		// Create a shallow copy to update the Name to match the requested resource name
		secret := *secretPtr
		secret.Name = resourceName

		anySecret, err := anypb.New(&secret)
		if err != nil {
			return nil, fmt.Errorf("marshaling secret: %w", err)
		}
		resources = append(resources, anySecret)
	}

	return &discovery.DiscoveryResponse{
		TypeUrl:   "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		Resources: resources,
	}, nil
}

// getOrCreateCert retrieves a cached cert or generates a new one.
func (s *Server) getOrCreateCert(domain string) (*tls.Secret, error) {
	s.cacheMu.RLock()
	if cached, ok := s.certCache[domain]; ok {
		s.cacheMu.RUnlock()
		return cached, nil
	}
	s.cacheMu.RUnlock()

	// Generate new certificate
	s.log.Info("generating certificate", "domain", domain)
	certPEM, keyPEM, err := s.ca.GenerateServerCert(domain, s.certTTL)
	if err != nil {
		s.log.Error(err, "failed to generate certificate", "domain", domain)
		return nil, err
	}
	s.log.Info("certificate generated successfully", "domain", domain)

	secret := &tls.Secret{
		Name: domain,
		Type: &tls.Secret_TlsCertificate{
			TlsCertificate: &tls.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: certPEM,
					},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: keyPEM,
					},
				},
			},
		},
	}
	s.log.Info("returning secret", "secret_name", secret.Name)

	// Cache it
	s.cacheMu.Lock()
	s.certCache[domain] = secret
	s.cacheMu.Unlock()

	return secret, nil
}

// ClearCache clears the certificate cache.
func (s *Server) ClearCache() {
	s.cacheMu.Lock()
	s.certCache = make(map[string]*tls.Secret)
	s.cacheMu.Unlock()
}

// CacheSize returns the number of cached certificates.
func (s *Server) CacheSize() int {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return len(s.certCache)
}
