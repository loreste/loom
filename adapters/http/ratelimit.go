package http

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimitConfig is a simple per-IP fixed-window limiter at the HTTP edge
// (before auth). Zero RequestsPerMinute disables the limiter.
//
// This is not a substitute for reverse-proxy limits; it reduces unauthenticated
// flood cost on /v1/execute and other routes. Fail closed: over limit → 429.
type RateLimitConfig struct {
	// RequestsPerMinute per client IP (0 = off).
	RequestsPerMinute int
	// Burst extra tokens above the per-minute rate (default = RequestsPerMinute).
	Burst int
	// Now optional clock for tests.
	Now func() time.Time
}

type ipBucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	rate     float64 // tokens per second
	burst    float64
	now      func() time.Time
	buckets  map[string]*ipBucket
	lastSweep time.Time
}

func newRateLimiter(cfg RateLimitConfig) *rateLimiter {
	if cfg.RequestsPerMinute <= 0 {
		return nil
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = cfg.RequestsPerMinute
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{
		rate:    float64(cfg.RequestsPerMinute) / 60.0,
		burst:   float64(burst),
		now:     now,
		buckets: make(map[string]*ipBucket),
	}
}

func (l *rateLimiter) allow(ip string) bool {
	if l == nil {
		return true
	}
	if ip == "" {
		ip = "unknown"
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// Opportunistic sweep of idle buckets every ~minute.
	if now.Sub(l.lastSweep) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) > 2*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}
	b := l.buckets[ip]
	if b == nil {
		b = &ipBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	// Prefer RemoteAddr only — do not trust X-Forwarded-For (spoofable unless
	// a trusted proxy is configured). Operators should rate-limit at the proxy.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
