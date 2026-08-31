package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// maxVisitors bounds the number of tracked rate-limit keys, so a flood of
// distinct source IPs cannot grow the visitor map without limit (memory DoS).
const maxVisitors = 65536

// RateLimiter implements per-IP rate limiting.
type RateLimiter struct {
	mu         sync.RWMutex
	visitors   map[string]*visitorLimiter
	rate       rate.Limit
	burst      int
	cleanup    time.Duration
	trustProxy bool
}

type visitorLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter.
// requestsPerMinute: maximum requests per minute
// burst: maximum burst size (requests allowed in quick succession)
// trustProxy: if true, honor X-Forwarded-For / X-Real-IP for the client key.
func NewRateLimiter(requestsPerMinute int, burst int, trustProxy bool) *RateLimiter {
	if burst <= 0 {
		burst = requestsPerMinute / 10
		if burst < 1 {
			burst = 1
		}
	}

	rl := &RateLimiter{
		visitors:   make(map[string]*visitorLimiter),
		rate:       rate.Limit(float64(requestsPerMinute) / 60.0), // Convert to per-second
		burst:      burst,
		cleanup:    5 * time.Minute,
		trustProxy: trustProxy,
	}

	// Start cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// getVisitor returns the rate limiter for a given IP, creating one if needed.
func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		// Bound the map: if full, evict the least-recently-seen entry so a
		// distinct-IP flood cannot exhaust memory.
		if len(rl.visitors) >= maxVisitors {
			rl.evictOldestLocked()
		}
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = &visitorLimiter{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

// evictSampleSize is the number of entries sampled for approximate-LRU eviction.
const evictSampleSize = 8

// evictOldestLocked removes an approximately least-recently-seen visitor. It
// samples a small, fixed number of entries (Go map iteration order is randomized)
// and evicts the oldest of the sample. This is O(1) per call rather than O(n),
// so a distinct-key flood that keeps the map at capacity cannot turn every insert
// into a full-map scan under the exclusive lock. Caller holds rl.mu.
func (rl *RateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldestSeen time.Time
	seen := 0
	for k, v := range rl.visitors {
		if seen == 0 || v.lastSeen.Before(oldestSeen) {
			oldestKey, oldestSeen = k, v.lastSeen
		}
		if seen++; seen >= evictSampleSize {
			break
		}
	}
	if seen > 0 {
		delete(rl.visitors, oldestKey)
	}
}

// cleanupLoop removes old visitors periodically.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > rl.cleanup {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	return rl.getVisitor(ip).Allow()
}

// Middleware returns an HTTP middleware that applies rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rateLimitKey(r, rl.trustProxy)

		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitConfig holds rate limit configuration.
type RateLimitConfig struct {
	GeneralLimit int  // Requests per minute for general endpoints
	UploadLimit  int  // Requests per minute for upload endpoints
	AuthLimit    int  // Requests per minute for auth endpoints (unlock/force-unlock)
	TrustProxy   bool // Honor X-Forwarded-For / X-Real-IP for the client key
}

// DefaultRateLimitConfig returns default rate limit configuration.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		GeneralLimit: 600, // 10 per second
		UploadLimit:  20,  // Prevent upload spam
		AuthLimit:    10,  // Slow down password / destructive attempts
	}
}

// RateLimitMiddleware creates rate limiting middleware with separate limits for different endpoints.
type RateLimitMiddleware struct {
	general *RateLimiter
	upload  *RateLimiter
	auth    *RateLimiter
}

// NewRateLimitMiddleware creates a new rate limit middleware with the given configuration.
func NewRateLimitMiddleware(cfg RateLimitConfig) *RateLimitMiddleware {
	authLimit := cfg.AuthLimit
	if authLimit <= 0 {
		authLimit = 10
	}
	return &RateLimitMiddleware{
		general: NewRateLimiter(cfg.GeneralLimit, cfg.GeneralLimit/10, cfg.TrustProxy),
		upload:  NewRateLimiter(cfg.UploadLimit, 5, cfg.TrustProxy),
		auth:    NewRateLimiter(authLimit, 5, cfg.TrustProxy),
	}
}

// General returns middleware for general rate limiting.
func (rlm *RateLimitMiddleware) General() func(http.Handler) http.Handler {
	return rlm.general.Middleware
}

// Upload returns middleware for upload rate limiting.
func (rlm *RateLimitMiddleware) Upload() func(http.Handler) http.Handler {
	return rlm.upload.Middleware
}

// Auth returns middleware for stricter rate limiting on authentication and
// destructive endpoints (unlock, force-unlock, lock).
func (rlm *RateLimitMiddleware) Auth() func(http.Handler) http.Handler {
	return rlm.auth.Middleware
}

// rateLimitKey returns the key used to bucket a request for rate limiting.
// By default it is the immediate peer address (RemoteAddr host), which a client
// cannot forge. Proxy headers are only trusted when trustProxy is set, since the
// documented deployment exposes the port directly and X-Forwarded-For would
// otherwise let any client mint unlimited buckets and fully bypass the limiter.
func rateLimitKey(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.IndexByte(xff, ','); idx >= 0 {
				xff = xff[:idx]
			}
			if xff = strings.TrimSpace(xff); xff != "" {
				return xff
			}
		}
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			return xri
		}
	}

	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		ip = ip[:idx]
	}
	return strings.Trim(ip, "[]")
}
