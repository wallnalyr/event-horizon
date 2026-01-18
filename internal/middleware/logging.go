package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	size        int
}

func wrapResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, status: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.status = code
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

// Logging logs HTTP requests in a secure manner.
// Only logs errors (4xx, 5xx) and slow requests (>5s) to reduce noise.
// It does NOT log:
// - Request/response bodies
// - Authorization headers
// - Session tokens
// - Any potentially sensitive data
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status
		wrapped := wrapResponseWriter(w)

		// Process request
		next.ServeHTTP(wrapped, r)

		// Calculate duration
		duration := time.Since(start)

		// Only log errors (4xx, 5xx) or slow requests (>5s)
		if wrapped.status >= 400 || duration > 5*time.Second {
			// Get client IP (check X-Forwarded-For for reverse proxy)
			clientIP := getClientIP(r)

			// Log in a structured format
			// SECURITY: Only log safe fields
			log.Printf(
				"%s %s %s %d %d %s %s",
				r.Method,
				sanitizePath(r.URL.Path),
				r.Proto,
				wrapped.status,
				wrapped.size,
				duration.Round(time.Millisecond),
				clientIP,
			)
		}
	})
}

// getClientIP extracts the client IP address from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For (first IP in the list)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr (strip port)
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		ip = ip[:idx]
	}
	// Handle IPv6 in brackets
	ip = strings.Trim(ip, "[]")

	return ip
}

// sanitizePath removes potentially sensitive information from the path.
func sanitizePath(path string) string {
	// Truncate very long paths
	if len(path) > 100 {
		path = path[:100] + "..."
	}

	// Replace potential file IDs with placeholder (keep first 4 chars for debugging)
	// This prevents logging full file IDs while still being useful for debugging
	parts := strings.Split(path, "/")
	for i, part := range parts {
		// If it looks like a hex ID (8+ hex chars), mask it
		if len(part) >= 8 && isHexString(part) {
			if len(part) > 4 {
				parts[i] = part[:4] + "****"
			}
		}
	}

	return strings.Join(parts, "/")
}

// isHexString checks if a string contains only hex characters.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Recovery recovers from panics and returns 500 error.
// SECURITY: Does not expose panic details to client.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log the panic (internal only)
				log.Printf("PANIC: %v (path: %s)", err, sanitizePath(r.URL.Path))

				// Return generic error to client (no details)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
