package controller

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-logr/logr"

	"github.com/spinningfactory/kloak/pkg/storage"
)

// Server provides the HTTP API for the Kloak controller.
type Server struct {
	store storage.Storage
	log   logr.Logger
}

// NewServer creates a new controller HTTP server.
func NewServer(store storage.Storage, log logr.Logger) *Server {
	return &Server{
		store: store,
		log:   log,
	}
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/store", s.handleStore)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	s.log.Info("starting controller HTTP server", "addr", addr)

	go func() {
		<-ctx.Done()
		s.log.Info("shutting down controller HTTP server")
		server.Shutdown(context.Background())
	}()

	return server.ListenAndServe()
}

type StoreRequest struct {
	Hash         string   `json:"hash"`
	Original     string   `json:"original"`
	AllowedHosts []string `json:"allowed_hosts"`
}

func (s *Server) handleStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Hash == "" || req.Original == "" {
		http.Error(w, "Missing hash or original value", http.StatusBadRequest)
		return
	}

	// Default to allow all hosts if not specified
	allowed := req.AllowedHosts
	if len(allowed) == 0 {
		allowed = []string{"*"}
	}

	s.log.Info("storing hash", "hash", req.Hash, "original", req.Original, "hosts", allowed)

	entry := storage.Entry{
		Value:        req.Original,
		AllowedHosts: allowed,
	}
	s.store.Store(r.Context(), "manual-http-store", req.Hash, entry)

	w.WriteHeader(http.StatusOK)
}
