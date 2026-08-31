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
//
// SECURITY: A reflected or wildcard origin is NEVER combined with
// Access-Control-Allow-Credentials: true. Only an origin that is explicitly
// listed in allowedOrigins (not "*") receives credentialed CORS. In wildcard
// mode we emit a bare "*" without credentials, which browsers refuse to pair
// with credentialed requests — preventing a malicious site from reading
// authenticated cross-origin responses.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	wildcard := containsWildcard(allowedOrigins)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			explicitlyAllowed := false
			for _, o := range allowedOrigins {
				if o != "*" && o == origin {
					explicitlyAllowed = true
					break
				}
			}

			switch {
			case explicitlyAllowed:
				// Trusted, explicitly-configured origin: full credentialed CORS.
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Token")
				w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
				w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")
			case wildcard:
				// Home-network wildcard: allow reads but WITHOUT credentials.
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Token")
				w.Header().Set("Access-Control-Max-Age", "86400")
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

// containsWildcard reports whether the allowed-origins list contains "*".
func containsWildcard(allowedOrigins []string) bool {
	for _, o := range allowedOrigins {
		if o == "*" {
			return true
		}
	}
	return false
}

// originHost returns the host[:port] of an Origin/Referer value, or "" if it
// cannot be parsed. e.g. "http://192.168.1.10:9000/x" -> "192.168.1.10:9000".
func originHost(origin string) string {
	if origin == "" {
		return ""
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
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

// OriginValidation validates the Origin header for state-changing requests to
// prevent CSRF. Safe methods (GET, HEAD, OPTIONS) and non-/api routes pass
// through. For state-changing /api requests the request Origin (or Referer
// fallback) is checked:
//
//   - Explicit allowlist mode: the origin must match a configured origin, or be
//     same-origin as the request host (so the app's own SPA always works).
//   - Wildcard ("*") / home-network mode: the origin must be SAME-ORIGIN as the
//     request host. A request that carries a cross-origin Origin/Referer is
//     rejected. This is the key fix: wildcard no longer means "skip CSRF checks".
//
// A state-changing /api request with NEITHER an Origin NOR a Referer is rejected
// (fail-closed). Browsers always attach an Origin header to cross-origin
// state-changing requests, so this does not affect the app's own SPA; it only
// requires non-browser clients (curl, scripts) to send an explicit Origin,
// which is a cheap safeguard for irreversible endpoints like force-unlock.
func OriginValidation(allowedOrigins []string) func(http.Handler) http.Handler {
	wildcard := containsWildcard(allowedOrigins)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip validation for safe methods (no state changes).
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			// Skip validation for non-API routes (static files, etc.).
			if !strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}

			// Get origin from Origin header or fall back to Referer.
			origin := r.Header.Get("Origin")
			if origin == "" {
				if referer := r.Header.Get("Referer"); referer != "" {
					if refURL, err := url.Parse(referer); err == nil {
						origin = refURL.Scheme + "://" + refURL.Host
					}
				}
			}

			// No Origin and no Referer on a state-changing /api request: reject
			// (fail-closed). Browsers always send Origin on cross-origin unsafe
			// requests, so only non-browser clients land here; they must send an
			// explicit Origin to reach destructive endpoints.
			if origin == "" {
				http.Error(w, "Origin validation failed: missing Origin header", http.StatusForbidden)
				return
			}

			// Same-origin requests are always allowed.
			if host := originHost(origin); host != "" && host == r.Host {
				next.ServeHTTP(w, r)
				return
			}

			// In wildcard mode, only same-origin is accepted for unsafe methods.
			if wildcard {
				http.Error(w, "Origin validation failed: cross-origin request rejected", http.StatusForbidden)
				return
			}

			// Explicit allowlist mode: origin must be listed.
			for _, o := range allowedOrigins {
				if o == origin {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Origin validation failed: origin not allowed", http.StatusForbidden)
		})
	}
}
