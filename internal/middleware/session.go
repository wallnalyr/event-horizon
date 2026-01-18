package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/fileez/fileez/internal/validate"
)

// SessionChecker is an interface for checking session state.
// This allows the middleware to check lock status without importing the store package.
type SessionChecker interface {
	IsLocked() bool
	GetToken() string
}

// ContextKey is a type for context keys to avoid collisions.
type ContextKey string

const (
	// SessionTokenKey is the context key for the session token.
	SessionTokenKey ContextKey = "sessionToken"
)

// SessionExtractor extracts and validates the session token from requests.
// The token can be provided in:
// 1. X-Session-Token header
// 2. Authorization header (Bearer token)
// 3. session_token query parameter
//
// The validated token is stored in the request context.
func SessionExtractor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string

		// Try X-Session-Token header first
		token = r.Header.Get("X-Session-Token")

		// Try Authorization header
		if token == "" {
			auth := r.Header.Get("Authorization")
			if len(auth) > 7 && auth[:7] == "Bearer " {
				token = auth[7:]
			}
		}

		// Try query parameter (least preferred)
		if token == "" {
			token = r.URL.Query().Get("session_token")
		}

		// Validate token if present
		if token != "" {
			validatedToken, err := validate.SessionToken(token)
			if err == nil {
				// Store validated token in context
				ctx := context.WithValue(r.Context(), SessionTokenKey, validatedToken)
				r = r.WithContext(ctx)
			}
			// Invalid tokens are silently ignored (treated as no token)
		}

		next.ServeHTTP(w, r)
	})
}

// GetSessionToken retrieves the session token from the request context.
// Returns empty string if no valid token is present.
func GetSessionToken(r *http.Request) string {
	if token, ok := r.Context().Value(SessionTokenKey).(string); ok {
		return token
	}
	return ""
}

// RequireSession is middleware that requires a valid session token.
// Returns 401 Unauthorized if no valid token is present.
func RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := GetSessionToken(r)
		if token == "" {
			http.Error(w, "Unauthorized: session token required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// OptionalSession is middleware that validates a session token if present but doesn't require it.
// Useful for endpoints that behave differently based on authentication status.
func OptionalSession(next http.Handler) http.Handler {
	// This is effectively the same as SessionExtractor, included for clarity in route definitions
	return SessionExtractor(next)
}

// LockedResponse is sent when a locked session requires authentication.
type LockedResponse struct {
	Locked  bool   `json:"locked"`
	Message string `json:"message,omitempty"`
}

// RequireSessionWhenLocked creates middleware that requires a valid session token when locked.
// If the session is not locked, requests pass through freely.
// If the session is locked, the request must have a valid session token that matches.
func RequireSessionWhenLocked(checker SessionChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if session is locked
			if !checker.IsLocked() {
				// Not locked - allow all requests
				next.ServeHTTP(w, r)
				return
			}

			// Session is locked - require valid token
			providedToken := GetSessionToken(r)
			expectedToken := checker.GetToken()

			if providedToken == "" || providedToken != expectedToken {
				// No token or wrong token - return locked response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(LockedResponse{
					Locked:  true,
					Message: "Session is locked. Please provide a valid session token.",
				})
				return
			}

			// Valid token - allow request
			next.ServeHTTP(w, r)
		})
	}
}
