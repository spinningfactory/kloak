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
	// Default cgroup root if not configured (should be configurable?)
	cgroupRoot := "/sys/fs/cgroup"

	// Use shared logic to find Pod cgroup
	podCgroupPath, err := cgroups.GetPodCgroupPath(cgroupRoot, req.PodUid, req.ContainerId)
	if err != nil {
		s.Log.Error(err, "failed to find pod cgroup", "pod", req.PodName, "uid", req.PodUid, "containerID", req.ContainerId)
		return nil, fmt.Errorf("failed to find pod cgroup: %v", err)
	}

	inode, err := cgroups.GetCgroupInodeFromPath(podCgroupPath)
	if err != nil {
		s.Log.Error(err, "failed to get cgroup inode", "path", podCgroupPath)
		return nil, fmt.Errorf("failed to get cgroup inode: %v", err)
	}

	s.Log.Info("CNI ADD: Programs eBPF for Pod", "pod", req.PodName, "cgroupPath", podCgroupPath, "inode", inode)

	if err := s.EBPFManager.AddCgroup(inode); err != nil {
		s.Log.Error(err, "failed to add cgroup to eBPF map")
		return nil, fmt.Errorf("failed to add cgroup to eBPF map: %v", err)
	}

	return &api.PodResponse{}, nil
}

func (s *CNIServer) handleDel(ctx context.Context, req *api.PodRequest) (*api.PodResponse, error) {
	// Default cgroup root
	cgroupRoot := "/sys/fs/cgroup"

	// Try to find the cgroup to get the inode
	// Note: During deletion, the cgroup might already be gone or hard to find if container is deleted.
	// However, we store the inode in the eBPF map (key).
	// Wait, the eBPF map key IS the inode.
	// If we can't find the cgroup, we can't get the inode, so we can't remove it from the map?
	// Actually, eBPF map clean up might be handled by the map itself if using LRU or similar?
	// No, it's a Hash map.
	// If the cgroup is gone, the ID (inode) is meaningless and might be reused.
	// We MUST remove it.

	podCgroupPath, err := cgroups.GetPodCgroupPath(cgroupRoot, req.PodUid, req.ContainerId)
	if err != nil {
		// If we can't find it, maybe it's already gone.
		s.Log.Info("CNI DEL: Cgroup not found, assuming already cleaned up", "err", err)
		return &api.PodResponse{}, nil
	}

	inode, err := cgroups.GetCgroupInodeFromPath(podCgroupPath)
	if err != nil {
		s.Log.Info("CNI DEL: Could not getting inode, assuming already cleaned up", "err", err)
		return &api.PodResponse{}, nil
	}

	s.Log.Info("CNI DEL: Removing eBPF for Pod", "pod", req.PodName, "inode", inode)
	if err := s.EBPFManager.RemoveCgroup(inode); err != nil {
		s.Log.Error(err, "failed to remove cgroup from eBPF map", "inode", inode)
		// Don't fail the CNI DEL, just log
	}

	return &api.PodResponse{}, nil
}
