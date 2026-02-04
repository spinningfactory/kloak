// Package xds provides the xDS server for Envoy configuration.
package xds

import (
	"context"
	"net"
	"sync"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"

	"github.com/dhia/bouncer/pkg/ca"
	"github.com/dhia/bouncer/pkg/extproc"
	"github.com/dhia/bouncer/pkg/sds"
	"github.com/dhia/bouncer/pkg/storage"
)

// Server manages the xDS services (SDS, ext_proc).
type Server struct {
	grpcServer *grpc.Server
	sdsServer  *sds.Server
	extProc    *extproc.Server
	log        logr.Logger
	addr       string

	mu      sync.Mutex
	started bool
}

// Config holds the configuration for the xDS server.
type Config struct {
	// SDSAddr is the address for the SDS server (port 15002)
	SDSAddr string
	// ExtProcAddr is the address for the ext_proc server (port 15003)
	ExtProcAddr string
}

// NewServer creates a combined xDS server with SDS and ext_proc.
func NewServer(rootCA *ca.CA, store storage.Storage, log logr.Logger) *Server {
	grpcServer := grpc.NewServer()

	sdsServer := sds.NewServer(rootCA, log.WithName("sds"))
	sdsServer.Register(grpcServer)

	extProcServer := extproc.NewServer(store, log.WithName("extproc"))
	extProcServer.Register(grpcServer)

	return &Server{
		grpcServer: grpcServer,
		sdsServer:  sdsServer,
		extProc:    extProcServer,
		log:        log,
	}
}

// Start starts the gRPC server on the given address.
func (s *Server) Start(ctx context.Context, addr string) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.addr = addr
	s.mu.Unlock()

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.log.Info("starting xDS server", "addr", addr)

	go func() {
		<-ctx.Done()
		s.log.Info("shutting down xDS server")
		s.grpcServer.GracefulStop()
	}()

	return s.grpcServer.Serve(lis)
}

// Stop stops the gRPC server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}

// SDSServer returns the SDS server instance.
func (s *Server) SDSServer() *sds.Server {
	return s.sdsServer
}

// ExtProcServer returns the ext_proc server instance.
func (s *Server) ExtProcServer() *extproc.Server {
	return s.extProc
}
