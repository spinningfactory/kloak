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

	"github.com/spinningfactory/kloak/pkg/ca"
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
func NewServer(ca *ca.CA, log logr.Logger) *Server {
	return &Server{
		ca:        ca,
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

// DeltaSecrets implements the delta xDS API for on-demand certificate fetching.
func (s *Server) DeltaSecrets(stream secret.SecretDiscoveryService_DeltaSecretsServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		// Process subscribed resources (new certificate requests)
		var resources []*discovery.Resource
		for _, resourceName := range req.ResourceNamesSubscribe {
			domain := resourceName

			// Handle default cert name
			if domain == "kloak-default-cert" || domain == "" {
				s.log.Info("generating default certificate", "requested_name", resourceName)
				domain = "localhost"
			} else {
				s.log.Info("generating certificate for domain (delta)", "domain", domain)
			}

			secretPtr, err := s.getOrCreateCert(domain)
			if err != nil {
				s.log.Error(err, "failed to generate cert", "domain", domain)
				continue
			}

			// Create a Secret with the requested name
			secretMsg := &tls.Secret{
				Name: resourceName,
				Type: &tls.Secret_TlsCertificate{
					TlsCertificate: secretPtr.GetTlsCertificate(),
				},
			}

			anySecret, err := anypb.New(secretMsg)
			if err != nil {
				s.log.Error(err, "failed to marshal secret", "domain", domain)
				continue
			}

			resources = append(resources, &discovery.Resource{
				Name:     resourceName,
				Resource: anySecret,
			})
		}

		// Send response with the requested certificates
		resp := &discovery.DeltaDiscoveryResponse{
			TypeUrl:          "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
			Resources:        resources,
			RemovedResources: req.ResourceNamesUnsubscribe,
		}

		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// handleRequest processes an SDS request and returns certificates.
func (s *Server) handleRequest(ctx context.Context, req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	var resources []*anypb.Any

	for _, resourceName := range req.ResourceNames {
		// resourceName is the SDS secret name, which should be the domain
		domain := resourceName

		// Handle predefined certificate names (fallback for default filter chain)
		if domain == "kloak-default-cert" || domain == "kloak-dynamic-cert" || domain == "default" {
			// Default catch-all: use a localhost certificate since we don't have SNI
			s.log.Info("generating default certificate for unknown SNI", "requested_name", domain)
			domain = "localhost"
		} else if domain == "" || domain == "DOWNSTREAM_TLS_SERVER_NAME" {
			// Fallback for when Envoy doesn't provide actual SNI
			return nil, fmt.Errorf("empty/invalid cert request")
		} else {
			// Domain-specific request - generate certificate for this domain
			s.log.Info("generating certificate for domain", "domain", domain)
		}

		secretPtr, err := s.getOrCreateCert(domain)
		if err != nil {
			return nil, fmt.Errorf("generating cert for %s: %w", domain, err)
		}

		// Create a new Secret based on the cached one, but with the requested name.
		// We CANNOT simply copy the struct (*secretPtr) because it contains a mutex (MessageState).
		secret := &tls.Secret{
			Name: resourceName,
			Type: &tls.Secret_TlsCertificate{
				TlsCertificate: secretPtr.GetTlsCertificate(),
			},
		}

		anySecret, err := anypb.New(secret)
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
	currentCA := s.ca
	if currentCA == nil {
		return nil, fmt.Errorf("CA not loaded")
	}

	certPEM, keyPEM, err := currentCA.GenerateServerCert([]string{domain}, 24*time.Hour)
	if err != nil {
		s.log.Error(err, "failed to generate certificate", "domain", domain)
		return nil, err
	}
	s.log.Info("certificate generated successfully", "domain", domain)

	// Build full certificate chain (leaf + CA)
	// This ensures clients can verify the chain even if they only have the root CA
	fullChain := append(certPEM, currentCA.CertPEM...)

	secret := &tls.Secret{
		Name: domain,
		Type: &tls.Secret_TlsCertificate{
			TlsCertificate: &tls.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: fullChain,
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
