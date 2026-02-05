// Package extproc provides the Envoy External Processor for header rewriting.
// It intercepts requests and replaces hashed header values with their originals.
package extproc

import (
	"context"
	"io"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dhia/bouncer/pkg/storage"
)

const (
	// HeaderPrefix is the prefix for hashed header values.
	HeaderPrefix = "bouncer:"
)

// Server implements the Envoy External Processor service.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer

	storage storage.Storage
	log     logr.Logger
}

// NewServer creates a new ext_proc server.
func NewServer(store storage.Storage, log logr.Logger) *Server {
	return &Server{
		storage: store,
		log:     log,
	}
}

// Register registers the ext_proc server with a gRPC server.
func (s *Server) Register(grpcServer *grpc.Server) {
	extprocv3.RegisterExternalProcessorServer(grpcServer, s)
}

// Process handles the bidirectional streaming RPC for request/response processing.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Internal, "failed to receive: %v", err)
		}

		resp, err := s.handleRequest(ctx, req)
		if err != nil {
			s.log.Error(err, "failed to handle request")
			continue
		}

		if err := stream.Send(resp); err != nil {
			return status.Errorf(codes.Internal, "failed to send: %v", err)
		}
	}
}

// handleRequest processes a single ext_proc request.
func (s *Server) handleRequest(ctx context.Context, req *extprocv3.ProcessingRequest) (*extprocv3.ProcessingResponse, error) {
	switch r := req.Request.(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		return s.handleRequestHeaders(ctx, r.RequestHeaders)
	default:
		// For other request types (body, trailers), just continue
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestHeaders{
				RequestHeaders: &extprocv3.HeadersResponse{
					Response: &extprocv3.CommonResponse{
						Status: extprocv3.CommonResponse_CONTINUE,
					},
				},
			},
		}, nil
	}
}

// handleRequestHeaders processes request headers and rewrites hashed values.
func (s *Server) handleRequestHeaders(ctx context.Context, headers *extprocv3.HttpHeaders) (*extprocv3.ProcessingResponse, error) {
	var mutations []*extprocv3.HeaderMutation

	for _, header := range headers.Headers.Headers {
		value := string(header.RawValue)
		if value == "" {
			value = header.Value
		}

		// Check if value is a bouncer hash
		if strings.HasPrefix(value, HeaderPrefix) {
			originalValue, found, err := s.storage.Lookup(ctx, value)
			if err != nil || !found {
				s.log.V(1).Info("hash not found in storage", "hash", value, "header", header.Key)
				continue
			}

			s.log.Info("rewriting header", "header", header.Key, "hash", value[:min(20, len(value))]+"...", "original", originalValue[:min(20, len(originalValue))]+"...")

			mutations = append(mutations, &extprocv3.HeaderMutation{
				SetHeaders: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:      header.Key,
							RawValue: []byte(originalValue),
						},
					},
				},
			})
		} else if strings.HasPrefix(value, "Bearer "+HeaderPrefix) {
			// Handle Bearer token
			token := strings.TrimPrefix(value, "Bearer ")
			originalValue, found, err := s.storage.Lookup(ctx, token)
			if err != nil || !found {
				s.log.V(1).Info("hash not found in storage (bearer)", "hash", token, "header", header.Key)
				continue
			}

			newValue := "Bearer " + originalValue
			s.log.Info("rewriting bearer header", "header", header.Key, "hash", token[:min(20, len(token))]+"...", "original", originalValue[:min(20, len(originalValue))]+"...")

			mutations = append(mutations, &extprocv3.HeaderMutation{
				SetHeaders: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:      header.Key,
							RawValue: []byte(newValue),
						},
					},
				},
			})
		}
	}

	resp := &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{
				Response: &extprocv3.CommonResponse{
					Status: extprocv3.CommonResponse_CONTINUE,
				},
			},
		},
	}

	// Apply mutations if any
	if len(mutations) > 0 {
		resp.Response = &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{
				Response: &extprocv3.CommonResponse{
					Status:         extprocv3.CommonResponse_CONTINUE,
					HeaderMutation: mutations[0], // Combine into one
				},
			},
		}

		// Merge all set headers into one mutation
		if len(mutations) > 1 {
			for i := 1; i < len(mutations); i++ {
				resp.GetRequestHeaders().Response.HeaderMutation.SetHeaders = append(
					resp.GetRequestHeaders().Response.HeaderMutation.SetHeaders,
					mutations[i].SetHeaders...,
				)
			}
		}
	}

	return resp, nil
}

// min returns the minimum of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
