// Package middleware provides HTTP middleware for security, logging, and rate limiting.
package middleware

import (
	"net/http"
	"net/url"
	"strings"
)

// SecurityHeaders adds security headers to all responses.
// Implements recommendations from OWASP Secure Headers Project.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Enable XSS filter (legacy browsers)
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions policy (disable unnecessary features)
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")

		// Content Security Policy
		csp := buildCSP()
		w.Header().Set("Content-Security-Policy", csp)

		// Strict Transport Security (only over HTTPS)
		// Note: This header is ignored over HTTP
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Cache control for API responses
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		next.ServeHTTP(w, r)
	})
}

// buildCSP builds the Content Security Policy header value.
func buildCSP() string {
	directives := []string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com", // Allow inline styles and Google Fonts CSS
		"img-src 'self' data: blob:",                                    // Allow data URIs and blobs for clipboard images
		"font-src 'self' https://fonts.gstatic.com",                     // Allow Google Fonts
		"connect-src 'self'",                                            // API calls
		"media-src 'self' blob:",                                        // For audio/video playback
		"object-src 'none'",                                             // Disable plugins
		"frame-src 'none'",                                              // No iframes
		"frame-ancestors 'none'",                                        // Prevent embedding
		"form-action 'self'",                                            // Form submissions only to self
		"base-uri 'self'",                                               // Prevent base tag hijacking
		"upgrade-insecure-requests",                                     // Upgrade HTTP to HTTPS
	}

	return strings.Join(directives, "; ")
}

// CORS adds CORS headers for cross-origin requests.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}

			if allowed && origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Token")
				w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
				w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// NoCache sets headers to prevent caching.
func NoCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

// RequestSizeLimit limits the request body size.
func RequestSizeLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// OriginValidation validates the Origin header for state-changing requests.
// This prevents CSRF attacks by ensuring requests come from allowed origins.
// Safe methods (GET, HEAD, OPTIONS) are allowed without origin validation.
// For home network apps with wildcard origins, all requests are allowed.
func OriginValidation(allowedOrigins []string) func(http.Handler) http.Handler {
	// Check if wildcard is allowed (home network mode) - skip all validation
	wildcardAllowed := false
	for _, o := range allowedOrigins {
		if o == "*" {
			wildcardAllowed = true
			break
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If wildcard is allowed, skip all origin validation (home network mode)
			if wildcardAllowed {
				next.ServeHTTP(w, r)
				return
			}

			// Skip validation for safe methods (no state changes)
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			// Skip validation for non-API routes (static files, etc.)
			if !strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}

			// Get origin from Origin header or fall back to Referer
			origin := r.Header.Get("Origin")
			if origin == "" {
				// For same-origin requests, browsers may not send Origin
				// Fall back to Referer header
				referer := r.Header.Get("Referer")
				if referer != "" {
					if refURL, err := url.Parse(referer); err == nil {
						origin = refURL.Scheme + "://" + refURL.Host
					}
				}
			}

			// If no origin can be determined, reject the request
			// This handles malicious requests that strip both headers
			if origin == "" {
				http.Error(w, "Origin validation failed: missing Origin header", http.StatusForbidden)
				return
			}

			// Validate origin against allowed list
			allowed := false
			for _, o := range allowedOrigins {
				if o == origin {
					allowed = true
					break
				}
			}

			if !allowed {
				http.Error(w, "Origin validation failed: origin not allowed", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
