package quotas

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/loreste/loom/core"
)

// RedisLimiter is a fixed-window distributed quota limiter.
//
// Adversarial defaults:
//   - FailClosed=true: Redis errors ⇒ deny (never fail open to unlimited)
//   - Lua script increments atomically and rolls back on exceed
//   - Unconfigured keys still unlimited unless Config.DefaultLimit > 0
type RedisLimiter struct {
	Cfg    *Config
	Client redis.Cmdable
	// FailClosed when true (default), store errors deny the request.
	FailClosed bool
	// KeyPrefix defaults to "loom:quota".
	KeyPrefix string
}

// Durable reports whether quota state is backed by Redis.
func (l *RedisLimiter) Durable() bool { return l != nil && l.Client != nil }

// NewRedisLimiter wraps a redis client. FailClosed defaults to true.
func NewRedisLimiter(client redis.Cmdable, cfg *Config) *RedisLimiter {
	if cfg == nil {
		cfg = NewConfig()
	}
	return &RedisLimiter{
		Cfg:        cfg,
		Client:     client,
		FailClosed: true,
		KeyPrefix:  "loom:quota",
	}
}

// SetLimit configures a window.
func (l *RedisLimiter) SetLimit(principal core.PrincipalID, boundary core.BoundaryID, op string, limit int64, interval time.Duration) error {
	if l == nil || l.Cfg == nil {
		return fmt.Errorf("%w: nil limiter", core.ErrInvalidArgument)
	}
	return l.Cfg.SetLimit(principal, boundary, op, limit, interval)
}

// quotaIncrScript: KEYS[1]=counter, ARGV[1]=n, ARGV[2]=ttl_ms, ARGV[3]=limit
// Returns new count, or -1 if exceeded (and decrements back).
var quotaIncrScript = redis.NewScript(`
local n = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local c = redis.call('INCRBY', KEYS[1], n)
if c == n then
  redis.call('PEXPIRE', KEYS[1], ttl)
end
if c > limit then
  redis.call('DECRBY', KEYS[1], n)
  return -1
end
return c
`)

// Allow implements Limiter.
func (l *RedisLimiter) Allow(ctx context.Context, id core.Identity, boundary core.BoundaryID, op string, n int64) error {
	if l == nil || l.Client == nil {
		return fmt.Errorf("quotas: redis limiter not configured")
	}
	if n <= 0 {
		n = 1
	}
	if l.Cfg == nil {
		// Fail closed: Cfg must be normalized by NewRedisLimiter, never
		// lazily mutated here (races under concurrent Allow).
		return fmt.Errorf("quotas: redis limiter not configured")
	}
	w, ok := l.Cfg.Resolve(id.ID, boundary, op)
	if !ok {
		return nil
	}

	// Validate BEFORE bucket math: a sub-millisecond interval has
	// Milliseconds()==0 and would divide by zero below.
	if w.Interval.Milliseconds() <= 0 {
		return fmt.Errorf("quotas: invalid interval")
	}
	now := time.Now()
	bucket := now.UnixMilli() / w.Interval.Milliseconds()
	key := CounterKey(l.KeyPrefix, id.ID, boundary, op, bucket)
	ttlMS := w.Interval.Milliseconds()
	// TTL slightly longer than window to avoid premature expiry
	if ttlMS < 1000 {
		ttlMS = 1000
	}
	ttlMS = ttlMS + 500

	res, err := quotaIncrScript.Run(ctx, l.Client, []string{key}, n, ttlMS, w.Limit).Int64()
	if err != nil {
		if l.FailClosed {
			return fmt.Errorf("quotas: redis unavailable (fail-closed): %w", err)
		}
		// Fail-open is discouraged; even with FailClosed=false we return an
		// error rather than silently allowing unlimited usage.
		return fmt.Errorf("quotas: redis error: %w", err)
	}
	if res < 0 {
		return fmt.Errorf("quota exceeded for %s (limit %d per %s)",
			LimitKey(id.ID, boundary, op), w.Limit, w.Interval)
	}
	return nil
}

// quotaRefundScript: KEYS[1]=counter, ARGV[1]=n
// Decrements the window counter, floors at 0 (deletes key), preserves TTL.
var quotaRefundScript = redis.NewScript(`
local n = tonumber(ARGV[1])
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local new = cur - n
if new <= 0 then
  redis.call('DEL', KEYS[1])
  return 0
end
local ttl = redis.call('PTTL', KEYS[1])
redis.call('SET', KEYS[1], new)
if ttl > 0 then
  redis.call('PEXPIRE', KEYS[1], ttl)
end
return new
`)

// Refund implements Limiter. Best-effort rollback of a prior Allow when the
// execution it gated failed. Redis errors are returned but never deny.
func (l *RedisLimiter) Refund(ctx context.Context, id core.Identity, boundary core.BoundaryID, op string, n int64) error {
	if l == nil || l.Client == nil || l.Cfg == nil {
		return nil
	}
	if n <= 0 {
		n = 1
	}
	w, ok := l.Cfg.Resolve(id.ID, boundary, op)
	if !ok {
		return nil // unlimited: nothing was consumed
	}
	if w.Interval.Milliseconds() <= 0 {
		return fmt.Errorf("quotas: invalid interval")
	}
	bucket := time.Now().UnixMilli() / w.Interval.Milliseconds()
	key := CounterKey(l.KeyPrefix, id.ID, boundary, op, bucket)
	_, err := quotaRefundScript.Run(ctx, l.Client, []string{key}, n).Int64()
	return err
}

// Ready pings Redis for /readyz.
func (l *RedisLimiter) Ready(ctx context.Context) error {
	if l == nil || l.Client == nil {
		return fmt.Errorf("quotas: redis not configured")
	}
	if pinger, ok := l.Client.(interface {
		Ping(context.Context) *redis.StatusCmd
	}); ok {
		return pinger.Ping(ctx).Err()
	}
	// Fallback: GET a missing key
	return l.Client.Get(ctx, l.KeyPrefix+":__ping__").Err()
}

// OpenClient creates a go-redis client from URL (redis://host:6379/0).
func OpenClient(redisURL string) (*redis.Client, error) {
	if redisURL == "" {
		return nil, fmt.Errorf("%w: empty redis url", core.ErrInvalidArgument)
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("redis url: %w", err)
	}
	// Timeouts: fail closed quickly rather than hang the pipeline
	if opt.DialTimeout == 0 {
		opt.DialTimeout = 2 * time.Second
	}
	if opt.ReadTimeout == 0 {
		opt.ReadTimeout = 1 * time.Second
	}
	if opt.WriteTimeout == 0 {
		opt.WriteTimeout = 1 * time.Second
	}
	client := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return client, nil
}
