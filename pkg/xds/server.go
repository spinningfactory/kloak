package xds

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-logr/logr"
	"github.com/spinningfactory/kloak/pkg/ca"
	"github.com/spinningfactory/kloak/pkg/extproc"
	"github.com/spinningfactory/kloak/pkg/lds"
	"github.com/spinningfactory/kloak/pkg/sds"
	"github.com/spinningfactory/kloak/pkg/storage"
	"google.golang.org/grpc"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	extension "github.com/envoyproxy/go-control-plane/envoy/service/extension/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	server "github.com/envoyproxy/go-control-plane/pkg/server/v3"
)

// Server implements the xDS server for Kloak.
type Server struct {
	server.Server
	snapshotCache cache.SnapshotCache
	ca            *ca.CA
	log           logr.Logger
	sdsServer     *sds.Server
	extProcServer *extproc.Server
}

// NewServer creates a new xDS server.
func NewServer(rootCA *ca.CA, store storage.Storage, log logr.Logger) *Server {
	// Create a snapshot cache
	c := cache.NewSnapshotCache(false, cache.IDHash{}, &snapshotLogger{log})

	// Create SDS server
	sdsSrv := sds.NewServer(rootCA, log.WithName("sds"))

	// Create ExtProc server
	extProcSrv := extproc.NewServer(store, log.WithName("extproc"))

	s := &Server{
		snapshotCache: c,
		ca:            rootCA,
		log:           log,
		sdsServer:     sdsSrv,
		extProcServer: extProcSrv,
	}

	// Create the xDS server callbacks
	cb := &callbacks{
		log:    log,
		server: s,
	}

	srv := server.NewServer(context.Background(), c, cb)
	s.Server = srv

	return s
}

// Run starts the gRPC server.
func (s *Server) Run(ctx context.Context, addr string) error {
	grpcServer := grpc.NewServer()

	// Register xDS services
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, s)
	extension.RegisterExtensionConfigDiscoveryServiceServer(grpcServer, s)

	// Register specific xDS services
	listener.RegisterListenerDiscoveryServiceServer(grpcServer, s)
	cluster.RegisterClusterDiscoveryServiceServer(grpcServer, s)
	route.RegisterRouteDiscoveryServiceServer(grpcServer, s)
	endpoint.RegisterEndpointDiscoveryServiceServer(grpcServer, s)

	// Register SDS server (our custom one)
	secret.RegisterSecretDiscoveryServiceServer(grpcServer, s.sdsServer)

	// Register ExtProc server
	s.extProcServer.Register(grpcServer)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.log.Info("starting xDS server", "addr", addr)

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	return grpcServer.Serve(lis)
}

// InitSnapshot creates the initial snapshot with the Listener.
// This is called when a new envoy connects.
func (s *Server) InitSnapshot(nodeID string) error {
	s.log.Info("init snapshot", "nodeID", nodeID)

	// Create the Listener using pkg/lds with on-demand certificate selection
	l, err := lds.MakeListener(15001)
	if err != nil {
		return err
	}

	version := fmt.Sprintf("%d", time.Now().UnixNano())
	snap, err := cache.NewSnapshot(version, map[resource.Type][]types.Resource{
		resource.ListenerType: {l},
		resource.ClusterType:  {},
		resource.RouteType:    {},
		resource.EndpointType: {},
	})
	if err != nil {
		return err
	}

	return s.snapshotCache.SetSnapshot(context.Background(), nodeID, snap)
}

type callbacks struct {
	log    logr.Logger
	server *Server
}

func (c *callbacks) OnStreamOpen(ctx context.Context, id int64, typ string) error {
	c.log.V(1).Info("stream open", "id", id, "type", typ)
	return nil
}
func (c *callbacks) OnStreamClosed(id int64, node *core.Node) {
	c.log.V(1).Info("stream closed", "id", id)
}
func (c *callbacks) OnStreamRequest(id int64, req *discovery.DiscoveryRequest) error {
	if req.Node == nil {
		c.log.Error(nil, "stream request missing node information", "type", req.TypeUrl)
		return nil
	}
	c.log.Info("stream request", "type", req.TypeUrl, "resources", req.ResourceNames, "node", req.Node.Id)

	// Check if snapshot exists for this node
	if _, err := c.server.snapshotCache.GetSnapshot(req.Node.Id); err != nil {
		// No snapshot, initialize it
		if err := c.server.InitSnapshot(req.Node.Id); err != nil {
			c.log.Error(err, "failed to init snapshot", "nodeID", req.Node.Id)
		}
	}

	return nil
}
func (c *callbacks) OnStreamResponse(ctx context.Context, id int64, req *discovery.DiscoveryRequest, res *discovery.DiscoveryResponse) {
	c.log.V(1).Info("stream response", "id", id, "type", res.TypeUrl)
}
func (c *callbacks) OnFetchRequest(ctx context.Context, req *discovery.DiscoveryRequest) error {
	return nil
}
func (c *callbacks) OnFetchResponse(req *discovery.DiscoveryRequest, res *discovery.DiscoveryResponse) {
}
func (c *callbacks) OnDeltaStreamOpen(ctx context.Context, id int64, typ string) error { return nil }
func (c *callbacks) OnDeltaStreamClosed(id int64, node *core.Node)                     {}
func (c *callbacks) OnStreamDeltaRequest(id int64, req *discovery.DeltaDiscoveryRequest) error {
	return nil
}
func (c *callbacks) OnStreamDeltaResponse(id int64, req *discovery.DeltaDiscoveryRequest, res *discovery.DeltaDiscoveryResponse) {
}

type snapshotLogger struct {
	log logr.Logger
}

func (l *snapshotLogger) Debugf(format string, args ...interface{}) {
	l.log.V(1).Info(fmt.Sprintf(format, args...))
}
func (l *snapshotLogger) Infof(format string, args ...interface{}) {
	l.log.Info(fmt.Sprintf(format, args...))
}
func (l *snapshotLogger) Warnf(format string, args ...interface{}) {
	l.log.Info(fmt.Sprintf("WARN: "+format, args...))
}
func (l *snapshotLogger) Errorf(format string, args ...interface{}) {
	l.log.Error(nil, fmt.Sprintf(format, args...))
}
