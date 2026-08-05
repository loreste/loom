package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/loreste/loom/bootstrap"
)

func TestRateLimitAllowsThenBlocks(t *testing.T) {
	var now time.Time
	now = time.Unix(1_700_000_000, 0)
	rl := newRateLimiter(RateLimitConfig{
		RequestsPerMinute: 60, // 1/sec
		Burst:             2,
		Now:               func() time.Time { return now },
	})
	if !rl.allow("1.2.3.4") || !rl.allow("1.2.3.4") {
		t.Fatal("burst of 2 must allow")
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("third request must deny")
	}
	// Other IP independent
	if !rl.allow("9.9.9.9") {
		t.Fatal("other IP must have its own bucket")
	}
	// Refill
	now = now.Add(2 * time.Second)
	if !rl.allow("1.2.3.4") {
		t.Fatal("after refill must allow")
	}
}

func TestRateLimitMiddlewareHTTP(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	srv, err := NewServer(p.Runtime, ServerConfig{
		RateLimit: RateLimitConfig{RequestsPerMinute: 30, Burst: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	// healthz is exempt
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("healthz blocked: %d", rr.Code)
		}
	}
	// execute burns tokens
	var last int
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/execute", nil)
		req.RemoteAddr = "10.0.0.2:9999"
		h.ServeHTTP(rr, req)
		last = rr.Code
		if rr.Code == http.StatusTooManyRequests {
			break
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("expected 429 eventually, last=%d", last)
	}
}
