package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fileez/fileez/internal/config"
	"github.com/fileez/fileez/internal/middleware"
	"github.com/fileez/fileez/internal/secure"
	"github.com/fileez/fileez/internal/store"
)

// Server holds all API dependencies.
type Server struct {
	Config    *config.Config
	Session   *store.SessionManager
	Files     *store.FileStore
	Clipboard *store.ClipboardStore
	Memory    *secure.MemoryTracker
}

// NewRouter creates and configures the HTTP router.
func NewRouter(s *Server) *chi.Mux {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.Recovery)
	r.Use(middleware.Logging)
	r.Use(middleware.SecurityHeaders)

	// Origin validation (CSRF protection)
	r.Use(middleware.OriginValidation(s.Config.AllowedOrigins))

	// CORS
	if s.Config.EnableCORS {
		r.Use(middleware.CORS(s.Config.AllowedOrigins))
	}

	// Rate limiting
	rateLimiter := middleware.NewRateLimitMiddleware(middleware.RateLimitConfig{
		GeneralLimit: s.Config.RateLimit,
		UploadLimit:  s.Config.UploadRateLimit,
	})

	// Session extraction (adds token to context if present)
	r.Use(middleware.SessionExtractor)

	// Create handlers
	healthHandler := NewHealthHandler(s.Memory, s.Files, s.Session)
	lockHandler := NewLockHandler(s.Session, s.Files, s.Clipboard)
	clipboardHandler := NewClipboardHandler(s.Clipboard, s.Session)
	filesHandler := NewFilesHandler(s.Files, s.Session, s.Config.MaxFileSize)

	// Session lock middleware - requires valid token when session is locked
	requireSessionWhenLocked := middleware.RequireSessionWhenLocked(s.Session)

	// Determine frontend directory
	frontendDir := s.Config.FrontendDir
	if frontendDir == "" {
		frontendDir = "./frontend/dist"
	}

	// API routes
	r.Route("/api", func(r chi.Router) {
		// Apply general rate limiting to API
		r.Use(rateLimiter.General())

		// Health endpoints (no rate limit override needed)
		r.Get("/health", healthHandler.Health)
		r.Get("/ping", healthHandler.Ping)

		// Lock/unlock endpoints
		r.Get("/lock/status", lockHandler.Status)
		r.Get("/lock/salt", lockHandler.GetSalt) // E2EE: Get salt for client-side key derivation
		r.Post("/lock", lockHandler.Lock)
		r.Post("/unlock", lockHandler.Unlock)
		r.Post("/lock/force-unlock", lockHandler.ForceUnlock)

		// Protected data routes - require session token when locked
		r.Group(func(r chi.Router) {
			r.Use(requireSessionWhenLocked)

			// Clipboard endpoints
			if s.Config.EnableClipboard {
				r.Get("/clipboard", clipboardHandler.GetText)
				r.Post("/clipboard", clipboardHandler.SetText)
				r.Delete("/clipboard", clipboardHandler.DeleteText)
			}

			// Clipboard image endpoints
			if s.Config.EnableClipboardImage {
				r.Get("/clipboard-image", clipboardHandler.GetImageInfo)
				r.Get("/clipboard-image/data", clipboardHandler.GetImageData)
				r.Post("/clipboard-image", clipboardHandler.SetImage)
				r.Delete("/clipboard-image", clipboardHandler.DeleteImage)
			}

			// File endpoints
			if s.Config.EnableFileSharing {
				r.Get("/files", filesHandler.List)

				// Upload with stricter rate limiting
				r.Group(func(r chi.Router) {
					r.Use(rateLimiter.Upload())
					r.Post("/upload", filesHandler.Upload)
					r.Post("/upload/encrypted", filesHandler.UploadEncrypted) // E2EE: encrypted file upload
				})

				r.Get("/files/{id}", filesHandler.GetMetadata)
				r.Get("/files/{id}/download", filesHandler.Download)
				r.Delete("/files/{id}", filesHandler.Delete)
			}
		})
	})

	// Serve root path
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		serveIndexHTML(w, req, frontendDir)
	})

	// Serve static assets (JS, CSS, images, etc.)
	fileServer := http.FileServer(http.Dir(frontendDir))
	r.Get("/assets/*", http.StripPrefix("/", fileServer).ServeHTTP)
	r.Get("/blackhole.svg", http.StripPrefix("/", fileServer).ServeHTTP)
	r.Get("/blackhole.png", http.StripPrefix("/", fileServer).ServeHTTP)
	r.Get("/manifest.json", http.StripPrefix("/", fileServer).ServeHTTP)
	r.Get("/favicon.ico", http.StripPrefix("/", fileServer).ServeHTTP)

	// SPA fallback - any other non-API GET routes serve index.html
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		// Only handle GET requests for SPA routing
		if req.Method != http.MethodGet {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		// Don't interfere with API routes
		if strings.HasPrefix(req.URL.Path, "/api/") {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		serveIndexHTML(w, req, frontendDir)
	})

	return r
}

// serveIndexHTML serves the index.html file for SPA routing.
func serveIndexHTML(w http.ResponseWriter, r *http.Request, dir string) {
	indexPath := filepath.Join(dir, "index.html")
	content, err := os.ReadFile(indexPath)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}
