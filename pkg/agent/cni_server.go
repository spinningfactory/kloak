package agent

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/go-logr/logr"
	"github.com/spinningfactory/kloak/pkg/cgroups"
	"github.com/spinningfactory/kloak/pkg/cni/api"
	"github.com/spinningfactory/kloak/pkg/ebpf"
	"google.golang.org/grpc"
)

const (
	// SocketPath is the path to the Kloak CNI agent socket
	SocketPath = "/run/kloak/cni.sock"
)

// CNIServer implements the CNI gRPC service
type CNIServer struct {
	api.UnimplementedCNIServer
	Log         logr.Logger
	EBPFManager *ebpf.EBPFCgroupManager
}

// NewCNIServer creates a new CNI server
func NewCNIServer(log logr.Logger, ebpfMgr *ebpf.EBPFCgroupManager) *CNIServer {
	return &CNIServer{
		Log:         log,
		EBPFManager: ebpfMgr,
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
	// CNI ADD is called very early during pod creation, often before the container cgroup exists.
	// The container cgroup is what bpf_get_current_cgroup_id() returns, and it's specific to each
	// container (.scope), not the pod (.slice).
	//
	// Since the container cgroup may not exist at CNI ADD time (the sandbox/pause container is
	// just being created), we try to find it but don't fail if it doesn't exist yet.
	// The controller will handle eBPF tracking once containers are running.
	cgroupRoot := "/sys/fs/cgroup"

	containerCgroupPath, err := cgroups.FindContainerCgroupPath(cgroupRoot, req.PodUid, req.ContainerId)
	if err != nil {
		// This is expected during early pod creation - cgroup may not exist yet
		s.Log.Info("CNI ADD: Container cgroup not found yet (expected during pod creation), controller will handle eBPF tracking",
			"pod", req.PodName, "uid", req.PodUid, "containerID", req.ContainerId)
		return &api.PodResponse{}, nil
	}

	inode, err := cgroups.GetCgroupInodeFromPath(containerCgroupPath)
	if err != nil {
		s.Log.Info("CNI ADD: Could not get cgroup inode, controller will handle eBPF tracking",
			"pod", req.PodName, "path", containerCgroupPath, "err", err)
		return &api.PodResponse{}, nil
	}

	s.Log.Info("CNI ADD: Programs eBPF for container", "pod", req.PodName, "cgroupPath", containerCgroupPath, "inode", inode)

	if err := s.EBPFManager.AddCgroup(inode); err != nil {
		s.Log.Error(err, "failed to add cgroup to eBPF map")
		// Don't fail CNI - controller will handle it
	}

	return &api.PodResponse{}, nil
}

func (s *CNIServer) handleDel(ctx context.Context, req *api.PodRequest) (*api.PodResponse, error) {
	// Default cgroup root
	cgroupRoot := "/sys/fs/cgroup"

	// Try to find the container's cgroup to get the inode
	// Note: During deletion, the cgroup might already be gone.
	containerCgroupPath, err := cgroups.FindContainerCgroupPath(cgroupRoot, req.PodUid, req.ContainerId)
	if err != nil {
		// If we can't find it, maybe it's already gone.
		s.Log.Info("CNI DEL: Cgroup not found, assuming already cleaned up", "err", err)
		return &api.PodResponse{}, nil
	}

	inode, err := cgroups.GetCgroupInodeFromPath(containerCgroupPath)
	if err != nil {
		s.Log.Info("CNI DEL: Could not get inode, assuming already cleaned up", "err", err)
		return &api.PodResponse{}, nil
	}

	s.Log.Info("CNI DEL: Removing eBPF for container", "pod", req.PodName, "inode", inode)
	if err := s.EBPFManager.RemoveCgroup(inode); err != nil {
		s.Log.Error(err, "failed to remove cgroup from eBPF map", "inode", inode)
		// Don't fail the CNI DEL, just log
	}

	return &api.PodResponse{}, nil
}
