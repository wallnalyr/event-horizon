package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimitKeyIgnoresSpoofedHeadersByDefault(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	r.RemoteAddr = "10.0.0.5:12345"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")

	if got := rateLimitKey(r, false); got != "10.0.0.5" {
		t.Fatalf("trustProxy=false: got %q, want 10.0.0.5 (must ignore spoofable headers)", got)
	}
	if got := rateLimitKey(r, true); got != "1.2.3.4" {
		t.Fatalf("trustProxy=true: got %q, want 1.2.3.4", got)
	}
}

func TestRateLimiterThrottlesSameKey(t *testing.T) {
	// 60/min = 1/sec, burst 2: the 3rd immediate request from one key is denied.
	rl := NewRateLimiter(60, 2, false)
	if !rl.Allow("k") || !rl.Allow("k") {
		t.Fatal("first two requests within burst should be allowed")
	}
	if rl.Allow("k") {
		t.Fatal("third immediate request should be throttled")
	}
	// A spoofed header cannot mint a fresh bucket when proxy is untrusted:
	// the middleware keys on RemoteAddr, verified by rateLimitKey above.
}

func TestVisitorMapIsBounded(t *testing.T) {
	rl := NewRateLimiter(600, 60, false)
	for i := 0; i < maxVisitors+1000; i++ {
		rl.Allow(string(rune(i%128)) + "-" + itoa(i))
	}
	rl.mu.RLock()
	n := len(rl.visitors)
	rl.mu.RUnlock()
	if n > maxVisitors {
		t.Fatalf("visitor map grew to %d, exceeds cap %d", n, maxVisitors)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
