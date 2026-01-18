package middleware

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter implements per-IP rate limiting.
type RateLimiter struct {
	mu       sync.RWMutex
	visitors map[string]*visitorLimiter
	rate     rate.Limit
	burst    int
	cleanup  time.Duration
}

type visitorLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter.
// requestsPerMinute: maximum requests per minute
// burst: maximum burst size (requests allowed in quick succession)
func NewRateLimiter(requestsPerMinute int, burst int) *RateLimiter {
	if burst <= 0 {
		burst = requestsPerMinute / 10
		if burst < 1 {
			burst = 1
		}
	}

	rl := &RateLimiter{
		visitors: make(map[string]*visitorLimiter),
		rate:     rate.Limit(float64(requestsPerMinute) / 60.0), // Convert to per-second
		burst:    burst,
		cleanup:  5 * time.Minute,
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
		ip := getClientIP(r)

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
	GeneralLimit int // Requests per minute for general endpoints
	UploadLimit  int // Requests per minute for upload endpoints
}

// DefaultRateLimitConfig returns default rate limit configuration.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		GeneralLimit: 600, // 10 per second
		UploadLimit:  20,  // Prevent upload spam
	}
}

// RateLimitMiddleware creates rate limiting middleware with separate limits for different endpoints.
type RateLimitMiddleware struct {
	general *RateLimiter
	upload  *RateLimiter
}

// NewRateLimitMiddleware creates a new rate limit middleware with the given configuration.
func NewRateLimitMiddleware(cfg RateLimitConfig) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		general: NewRateLimiter(cfg.GeneralLimit, cfg.GeneralLimit/10),
		upload:  NewRateLimiter(cfg.UploadLimit, 5),
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
