package sync

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"github.com/spinningfactory/kloak/pkg/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client connects to the controller's sync service and populates local storage.
type Client struct {
	controllerAddr string
	storage        storage.Storage
	log            logr.Logger
	namespaces     []string

	conn   *grpc.ClientConn
	client SyncServiceClient
}

// NewClient creates a new sync client.
func NewClient(controllerAddr string, store storage.Storage, log logr.Logger) *Client {
	return &Client{
		controllerAddr: controllerAddr,
		storage:        store,
		log:            log,
	}
}

// SetNamespaceFilter sets the namespace filter for watching secrets.
func (c *Client) SetNamespaceFilter(namespaces []string) {
	c.namespaces = namespaces
}

// Connect establishes connection to the controller.
func (c *Client) Connect(ctx context.Context) error {
	c.log.Info("connecting to controller", "addr", c.controllerAddr)

	conn, err := grpc.DialContext(ctx, c.controllerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return err
	}

	c.conn = conn
	c.client = NewSyncServiceClient(conn)
	c.log.Info("connected to controller")
	return nil
}

// Close closes the connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Run starts watching for secret updates and populates local storage.
// It reconnects automatically on failure.
func (c *Client) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := c.watch(ctx); err != nil {
			c.log.Error(err, "watch disconnected, reconnecting in 5s")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// watch establishes a watch stream and processes events.
func (c *Client) watch(ctx context.Context) error {
	// Connect if not connected
	if c.client == nil {
		if err := c.Connect(ctx); err != nil {
			return err
		}
	}

	req := &WatchSecretsRequest{
		Namespaces: c.namespaces,
	}

	stream, err := c.client.WatchSecrets(ctx, req)
	if err != nil {
		c.client = nil
		c.conn = nil
		return err
	}

	c.log.Info("watch stream established", "namespaces", c.namespaces)

	for {
		event, err := stream.Recv()
		if err != nil {
			return err
		}

		if err := c.handleEvent(ctx, event); err != nil {
			c.log.Error(err, "failed to handle event", "type", event.Type, "hash", event.Hash)
		}
	}
}

// handleEvent processes a single secret event.
func (c *Client) handleEvent(ctx context.Context, event *SecretEvent) error {
	switch event.Type {
	case EventType_EVENT_TYPE_ADD, EventType_EVENT_TYPE_UPDATE, EventType_EVENT_TYPE_SYNC:
		entry := storage.Entry{
			Value:        event.Value,
			AllowedHosts: event.AllowedHosts,
		}
		if err := c.storage.Store(ctx, event.PodId, event.Hash, entry); err != nil {
			return err
		}
		c.log.V(1).Info("stored secret", "hash", event.Hash, "type", event.Type)

	case EventType_EVENT_TYPE_DELETE:
		if err := c.storage.Delete(ctx, event.PodId); err != nil {
			return err
		}
		c.log.V(1).Info("deleted secret", "hash", event.Hash, "podID", event.PodId)
	}

	return nil
}

// FetchAll fetches all secrets from controller (pull model).
func (c *Client) FetchAll(ctx context.Context) error {
	if c.client == nil {
		if err := c.Connect(ctx); err != nil {
			return err
		}
	}

	resp, err := c.client.GetSecrets(ctx, &GetSecretsRequest{
		Namespaces: c.namespaces,
	})
	if err != nil {
		return err
	}

	for _, secret := range resp.Secrets {
		entry := storage.Entry{
			Value:        secret.Value,
			AllowedHosts: secret.AllowedHosts,
		}
		if err := c.storage.Store(ctx, secret.PodId, secret.Hash, entry); err != nil {
			c.log.Error(err, "failed to store secret", "hash", secret.Hash)
		}
	}

	c.log.Info("fetched all secrets", "count", len(resp.Secrets))
	return nil
}
