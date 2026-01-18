// Package api provides HTTP handlers for the FileEZ API.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/fileez/fileez/internal/secure"
	"github.com/fileez/fileez/internal/store"
)

// HealthHandler handles health check requests.
type HealthHandler struct {
	memory  *secure.MemoryTracker
	files   *store.FileStore
	session *store.SessionManager
}

// NewHealthHandler creates a new health handler.
func NewHealthHandler(memory *secure.MemoryTracker, files *store.FileStore, session *store.SessionManager) *HealthHandler {
	return &HealthHandler{
		memory:  memory,
		files:   files,
		session: session,
	}
}

// HealthResponse is the response for health check.
type HealthResponse struct {
	Status  string              `json:"status"`
	Memory  *secure.MemoryStats `json:"memory,omitempty"`
	Files   *store.FileStoreStats `json:"files,omitempty"`
	Session *store.SessionStatus  `json:"session,omitempty"`
}

// Health handles GET /api/health
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status: "ok",
	}

	// Include stats if requested
	if r.URL.Query().Get("stats") == "true" {
		if h.memory != nil {
			stats := h.memory.Stats()
			resp.Memory = &stats
		}
		if h.files != nil {
			stats := h.files.Stats()
			resp.Files = &stats
		}
		if h.session != nil {
			status := h.session.Status()
			resp.Session = &status
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Ping handles GET /api/ping (simple health check)
func (h *HealthHandler) Ping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("pong"))
}
