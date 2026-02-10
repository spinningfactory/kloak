// Package sync provides secret synchronization between controller and agents.
package sync

import (
	"sync"

	"github.com/go-logr/logr"
	"github.com/spinningfactory/kloak/pkg/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the SyncService gRPC server.
// It runs on the controller and streams secret updates to agents.
type Server struct {
	UnimplementedSyncServiceServer

	storage storage.Storage
	log     logr.Logger

	// subscribers tracks active watch streams
	subscribers   map[string]chan *SecretEvent
	subscribersMu sync.RWMutex
	nextSubID     int
}

// NewServer creates a new sync server.
func NewServer(store storage.Storage, log logr.Logger) *Server {
	return &Server{
		storage:     store,
		log:         log,
		subscribers: make(map[string]chan *SecretEvent),
	}
}

// Register registers the server with a gRPC server.
func (s *Server) Register(grpcServer *grpc.Server) {
	RegisterSyncServiceServer(grpcServer, s)
}

// WatchSecrets streams secret updates to agents.
func (s *Server) WatchSecrets(req *WatchSecretsRequest, stream SyncService_WatchSecretsServer) error {
	// Create subscriber channel
	s.subscribersMu.Lock()
	s.nextSubID++
	subID := string(rune(s.nextSubID))
	ch := make(chan *SecretEvent, 100)
	s.subscribers[subID] = ch
	s.subscribersMu.Unlock()

	s.log.Info("new watch subscriber", "id", subID, "namespaces", req.Namespaces)

	defer func() {
		s.subscribersMu.Lock()
		delete(s.subscribers, subID)
		close(ch)
		s.subscribersMu.Unlock()
		s.log.Info("watch subscriber disconnected", "id", subID)
	}()

	// Send initial sync of all secrets
	if err := s.sendInitialSync(stream, req.Namespaces); err != nil {
		return err
	}

	// Stream updates
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case event, ok := <-ch:
			if !ok {
				return nil
			}
			// Filter by namespace if specified
			if len(req.Namespaces) > 0 && !contains(req.Namespaces, event.Namespace) {
				continue
			}
			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}

// sendInitialSync sends all current secrets to a new subscriber.
func (s *Server) sendInitialSync(stream SyncService_WatchSecretsServer, namespaces []string) error {
	secrets, err := s.storage.List(stream.Context())
	if err != nil {
		return status.Errorf(codes.Internal, "failed to list secrets: %v", err)
	}

	for hash, entry := range secrets {
		event := &SecretEvent{
			Type:         EventType_EVENT_TYPE_SYNC,
			Hash:         hash,
			Value:        entry.Value,
			AllowedHosts: entry.AllowedHosts,
		}
		if err := stream.Send(event); err != nil {
			return err
		}
	}

	s.log.Info("sent initial sync", "count", len(secrets))
	return nil
}

// broadcast sends an event to all subscribers.
func (s *Server) broadcast(event *SecretEvent) {
	s.subscribersMu.RLock()
	defer s.subscribersMu.RUnlock()

	for id, ch := range s.subscribers {
		select {
		case ch <- event:
		default:
			s.log.V(1).Info("subscriber channel full, dropping event", "id", id)
		}
	}
}

// NotifyDelete notifies subscribers of a secret deletion.
func (s *Server) NotifyDelete(hash, podID, namespace string) {
	s.broadcast(&SecretEvent{
		Type:      EventType_EVENT_TYPE_DELETE,
		Hash:      hash,
		PodId:     podID,
		Namespace: namespace,
	})
}

// NotifyUpdate notifies subscribers of a secret update.
func (s *Server) NotifyUpdate(hash string, entry storage.Entry, namespace string) {
	s.broadcast(&SecretEvent{
		Type:         EventType_EVENT_TYPE_UPDATE,
		Hash:         hash,
		Value:        entry.Value,
		AllowedHosts: entry.AllowedHosts,
		Namespace:    namespace,
	})
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
