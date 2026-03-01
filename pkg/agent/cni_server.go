package agent

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/go-logr/logr"
	"github.com/spinningfactory/kloak/pkg/cni/api"
	"google.golang.org/grpc"
)

const (
	// SocketPath is the path to the Kloak CNI agent socket
	SocketPath = "/run/kloak/cni.sock"
)

// CNIServer implements the CNI gRPC service
type CNIServer struct {
	api.UnimplementedCNIServer
	Log logr.Logger
}

// NewCNIServer creates a new CNI server
func NewCNIServer(log logr.Logger) *CNIServer {
	return &CNIServer{
		Log: log,
	}
}

// Start starts the gRPC server on the UDS
func (s *CNIServer) Start(ctx context.Context) error {
	// Clean up old socket
	if _, err := os.Stat(SocketPath); err == nil {
		if err := os.Remove(SocketPath); err != nil {
			return fmt.Errorf("failed to remove old socket: %v", err)
		}
	}

	// Create listener
	lis, err := net.Listen("unix", SocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()
	api.RegisterCNIServer(grpcServer, s)

	s.Log.Info("CNI server listening on UDS", "path", SocketPath)

	// Run in goroutine
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			s.Log.Error(err, "CNI server failed")
		}
	}()

	// Wait for context cancellation to stop
	<-ctx.Done()
	grpcServer.GracefulStop()
	return nil
}

// HandlePod processes CNI ADD/DEL requests
func (s *CNIServer) HandlePod(ctx context.Context, req *api.PodRequest) (*api.PodResponse, error) {
	s.Log.Info("Received CNI request",
		"command", req.Command,
		"pod", fmt.Sprintf("%s/%s", req.PodNamespace, req.PodName),
		"containerID", req.ContainerId,
		"netns", req.Netns,
	)

	switch req.Command {
	case api.Command_ADD:
		return s.handleAdd(ctx, req)
	case api.Command_DEL:
		return s.handleDel(ctx, req)
	default:
		return nil, fmt.Errorf("unknown command: %v", req.Command)
	}
}

func (s *CNIServer) handleAdd(ctx context.Context, req *api.PodRequest) (*api.PodResponse, error) {
	s.Log.Info("CNI ADD: Received request, controller handles uprobe tracking", "pod", req.PodName, "containerID", req.ContainerId)
	return &api.PodResponse{}, nil
}

func (s *CNIServer) handleDel(ctx context.Context, req *api.PodRequest) (*api.PodResponse, error) {
	s.Log.Info("CNI DEL: Received request, uprobes auto-detach on process exit", "pod", req.PodName, "containerID", req.ContainerId)
	return &api.PodResponse{}, nil
}
