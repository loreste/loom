// Package quotas enforces rate and usage limits. Exceeded ⇒ deny.
package quotas

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// Limiter checks and consumes quota.
type Limiter interface {
	// Allow returns nil if under quota (and consumes n). Error = deny.
	Allow(ctx context.Context, id core.Identity, boundary core.BoundaryID, op string, n int64) error
	// Refund returns n units consumed by a prior successful Allow, used when
	// the execution it gated failed (handler error or pre-handler cancel).
	// Best-effort: a refund error must never deny; the runtime logs it.
	Refund(ctx context.Context, id core.Identity, boundary core.BoundaryID, op string, n int64) error
}

// Window is a fixed window counter.
type Window struct {
	Limit    int64
	Interval time.Duration
}

// MemoryLimiter is a fixed-window in-memory limiter.
// Default: if no limit configured for a key, allow (unlimited).
// Set DefaultLimit > 0 (via Config) to fail-closed for unconfigured keys.
type MemoryLimiter struct {
	Cfg   *Config
	mu    sync.Mutex
	state map[string]*windowState
}

// Durable reports whether quota state survives process restart. Memory quota
// state is process-local and must not be used for production coordination.
func (l *MemoryLimiter) Durable() bool { return false }

type windowState struct {
	count int64
	reset time.Time
}

// NewMemoryLimiter creates a limiter with its own Config.
func NewMemoryLimiter() *MemoryLimiter {
	return &MemoryLimiter{
		Cfg:   NewConfig(),
		state: make(map[string]*windowState),
	}
}

// NewMemoryLimiterWithConfig shares limit definitions (e.g. with Redis limiter).
func NewMemoryLimiterWithConfig(cfg *Config) *MemoryLimiter {
	if cfg == nil {
		cfg = NewConfig()
	}
	return &MemoryLimiter{Cfg: cfg, state: make(map[string]*windowState)}
}

// SetLimit configures a window (delegates to Config).
func (l *MemoryLimiter) SetLimit(principal core.PrincipalID, boundary core.BoundaryID, op string, limit int64, interval time.Duration) error {
	if l == nil || l.Cfg == nil {
		return fmt.Errorf("%w: nil limiter", core.ErrInvalidArgument)
	}
	return l.Cfg.SetLimit(principal, boundary, op, limit, interval)
}

// Allow implements Limiter.
func (l *MemoryLimiter) Allow(_ context.Context, id core.Identity, boundary core.BoundaryID, op string, n int64) error {
	if l == nil {
		return fmt.Errorf("quotas: limiter not configured")
	}
	if n <= 0 {
		n = 1
	}
	if l.Cfg == nil {
		// Fail closed: Cfg must be normalized by the constructor, never
		// lazily mutated here (races under concurrent Allow).
		return fmt.Errorf("quotas: limiter not configured")
	}
	w, ok := l.Cfg.Resolve(id.ID, boundary, op)
	if !ok {
		return nil // unlimited
	}

	key := LimitKey(id.ID, boundary, op)
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.state[key]
	now := time.Now()
	if st == nil || now.After(st.reset) {
		st = &windowState{count: 0, reset: now.Add(w.Interval)}
		l.state[key] = st
	}
	if st.count+n > w.Limit {
		return fmt.Errorf("quota exceeded for %s (limit %d per %s)", key, w.Limit, w.Interval)
	}
	st.count += n
	return nil
}

// Refund implements Limiter. Best-effort: if the window rolled over since the
// Allow, the refund applies to the current window (or is a no-op) — acceptable.
func (l *MemoryLimiter) Refund(_ context.Context, id core.Identity, boundary core.BoundaryID, op string, n int64) error {
	if l == nil || l.Cfg == nil {
		return nil
	}
	if n <= 0 {
		n = 1
	}
	if _, ok := l.Cfg.Resolve(id.ID, boundary, op); !ok {
		return nil // unlimited: nothing was consumed
	}
	key := LimitKey(id.ID, boundary, op)
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.state[key]
	if st == nil {
		return nil
	}
	st.count -= n
	if st.count < 0 {
		st.count = 0
	}
	return nil
}
