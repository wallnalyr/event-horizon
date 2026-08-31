package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReq(method, target, origin string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "192.168.1.10:9000"
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func runOrigin(allowed []string, r *http.Request) int {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rec := httptest.NewRecorder()
	OriginValidation(allowed)(next).ServeHTTP(rec, r)
	return rec.Code
}

func TestOriginValidationWildcardBlocksCrossOrigin(t *testing.T) {
	wildcard := []string{"*"}

	// Cross-origin state-changing request must be rejected even in wildcard mode.
	if code := runOrigin(wildcard, newReq(http.MethodPost, "http://192.168.1.10:9000/api/lock/force-unlock", "http://evil.com")); code != http.StatusForbidden {
		t.Fatalf("cross-origin POST: got %d, want 403", code)
	}

	// Same-origin state-changing request is allowed.
	if code := runOrigin(wildcard, newReq(http.MethodPost, "http://192.168.1.10:9000/api/clipboard", "http://192.168.1.10:9000")); code != http.StatusOK {
		t.Fatalf("same-origin POST: got %d, want 200", code)
	}

	// GET is a safe method and always passes.
	if code := runOrigin(wildcard, newReq(http.MethodGet, "http://192.168.1.10:9000/api/files", "http://evil.com")); code != http.StatusOK {
		t.Fatalf("cross-origin GET: got %d, want 200", code)
	}

	// State-changing request with no Origin/Referer is rejected (fail-closed).
	if code := runOrigin(wildcard, newReq(http.MethodPost, "http://192.168.1.10:9000/api/clipboard", "")); code != http.StatusForbidden {
		t.Fatalf("no-origin POST: got %d, want 403", code)
	}
}

func TestOriginValidationExplicitAllowlist(t *testing.T) {
	allowed := []string{"https://trusted.lan"}

	if code := runOrigin(allowed, newReq(http.MethodPost, "http://192.168.1.10:9000/api/clipboard", "https://trusted.lan")); code != http.StatusOK {
		t.Fatalf("listed origin: got %d, want 200", code)
	}
	if code := runOrigin(allowed, newReq(http.MethodPost, "http://192.168.1.10:9000/api/clipboard", "https://evil.com")); code != http.StatusForbidden {
		t.Fatalf("unlisted origin: got %d, want 403", code)
	}
	// The app's own SPA (same-origin) works even if not explicitly listed.
	if code := runOrigin(allowed, newReq(http.MethodPost, "http://192.168.1.10:9000/api/clipboard", "http://192.168.1.10:9000")); code != http.StatusOK {
		t.Fatalf("same-origin: got %d, want 200", code)
	}
}

func TestCORSCredentialsOnlyForExplicitOrigin(t *testing.T) {
	// Wildcard mode: reflect must NOT carry credentials.
	rec := httptest.NewRecorder()
	r := newReq(http.MethodGet, "http://192.168.1.10:9000/api/files", "http://evil.com")
	CORS([]string{"*"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, r)
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got == "true" {
		t.Fatalf("wildcard mode must not set Allow-Credentials:true")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("wildcard mode ACAO: got %q, want *", got)
	}

	// Explicit origin: credentialed CORS is allowed.
	rec2 := httptest.NewRecorder()
	r2 := newReq(http.MethodGet, "http://192.168.1.10:9000/api/files", "https://trusted.lan")
	CORS([]string{"https://trusted.lan"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec2, r2)
	if got := rec2.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("explicit origin should set Allow-Credentials:true, got %q", got)
	}
	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "https://trusted.lan" {
		t.Fatalf("explicit origin ACAO: got %q", got)
	}
}
