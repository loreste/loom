package quotas_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/quotas"
)

func TestRedisLimiterAllowAndExceed(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cfg := quotas.NewConfig()
	_ = cfg.SetLimit("user:bob", "dev", "payment.capture", 3, time.Minute)
	lim := quotas.NewRedisLimiter(rdb, cfg)

	id := core.Identity{ID: "user:bob"}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := lim.Allow(ctx, id, "dev", "payment.capture", 1); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if err := lim.Allow(ctx, id, "dev", "payment.capture", 1); err == nil {
		t.Fatal("expected exceed")
	}
}

func TestRedisRollbackOnExceed(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cfg := quotas.NewConfig()
	_ = cfg.SetLimit("user:bob", "dev", "payment.capture", 3, time.Minute)
	lim := quotas.NewRedisLimiter(rdb, cfg)

	id := core.Identity{ID: "user:bob"}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := lim.Allow(ctx, id, "dev", "payment.capture", 1); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if err := lim.Allow(ctx, id, "dev", "payment.capture", 1); err == nil {
		t.Fatal("expected exceed")
	}

	// Adversarial: the rejected call must have been rolled back (DECRBY),
	// leaving the counter at the limit — not limit+1.
	var counters []string
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, "loom:quota:") {
			counters = append(counters, k)
		}
	}
	if len(counters) != 1 {
		t.Fatalf("expected 1 quota counter key, got %v", counters)
	}
	got, err := mr.Get(counters[0])
	if err != nil {
		t.Fatalf("counter read: %v", err)
	}
	if got != "3" {
		t.Fatalf("rollback missing: counter=%s want 3 (rejected call leaked into count)", got)
	}

	// A later rejected call must not drift the counter further.
	if err := lim.Allow(ctx, id, "dev", "payment.capture", 1); err == nil {
		t.Fatal("expected exceed")
	}
	got, err = mr.Get(counters[0])
	if err != nil {
		t.Fatalf("counter read: %v", err)
	}
	if got != "3" {
		t.Fatalf("counter drifted after second reject: %s want 3", got)
	}
}

func TestRedisFailClosedOnDown(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cfg := quotas.NewConfig()
	_ = cfg.SetLimit("user:a", "dev", "op", 10, time.Minute)
	lim := quotas.NewRedisLimiter(rdb, cfg)
	lim.FailClosed = true
	mr.Close() // kill redis

	err := lim.Allow(context.Background(), core.Identity{ID: "user:a"}, "dev", "op", 1)
	if err == nil {
		t.Fatal("must fail closed when redis down")
	}
}

func TestRedisUnlimitedWhenNoConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	lim := quotas.NewRedisLimiter(rdb, quotas.NewConfig())
	if err := lim.Allow(context.Background(), core.Identity{ID: "x"}, "dev", "y", 1); err != nil {
		t.Fatal(err)
	}
}

func TestRedisDefaultLimit(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	cfg := quotas.NewConfig()
	cfg.DefaultLimit = 2
	cfg.DefaultInterval = time.Minute
	lim := quotas.NewRedisLimiter(rdb, cfg)
	id := core.Identity{ID: "u"}
	_ = lim.Allow(context.Background(), id, "b", "o", 1)
	_ = lim.Allow(context.Background(), id, "b", "o", 1)
	if err := lim.Allow(context.Background(), id, "b", "o", 1); err == nil {
		t.Fatal("default limit should bind")
	}
}

// TestRedisSubMillisecondIntervalNoPanic: a sub-millisecond interval has
// Milliseconds()==0; Allow must reject it before the bucket divide, and must
// error before touching Redis (client here points nowhere and is never dialed).
func TestRedisSubMillisecondIntervalNoPanic(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
	t.Cleanup(func() { _ = rdb.Close() })
	cfg := quotas.NewConfig()
	if err := cfg.SetLimit("user:a", "dev", "op", 5, 500*time.Microsecond); err != nil {
		t.Fatal(err)
	}
	lim := quotas.NewRedisLimiter(rdb, cfg)
	err := lim.Allow(context.Background(), core.Identity{ID: "user:a"}, "dev", "op", 1)
	if err == nil {
		t.Fatal("expected invalid interval error")
	}
	if got := err.Error(); !strings.Contains(got, "invalid interval") {
		t.Fatalf("err = %v, want invalid interval", err)
	}
}

// TestLimiterNilCfgFailsClosed: a limiter built by hand (nil Cfg) must error
// in Allow, not lazily mutate shared state (race) or fail open.
func TestLimiterNilCfgFailsClosed(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
	t.Cleanup(func() { _ = rdb.Close() })
	rl := &quotas.RedisLimiter{Client: rdb}
	if err := rl.Allow(context.Background(), core.Identity{ID: "u"}, "b", "o", 1); err == nil {
		t.Fatal("redis limiter with nil Cfg must fail closed")
	}
	ml := &quotas.MemoryLimiter{}
	if err := ml.Allow(context.Background(), core.Identity{ID: "u"}, "b", "o", 1); err == nil {
		t.Fatal("memory limiter with nil Cfg must fail closed")
	}
}

func TestRedisLimiterRefund(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cfg := quotas.NewConfig()
	_ = cfg.SetLimit("user:bob", "dev", "payment.capture", 1, time.Minute)
	lim := quotas.NewRedisLimiter(rdb, cfg)

	id := core.Identity{ID: "user:bob"}
	ctx := context.Background()
	if err := lim.Allow(ctx, id, "dev", "payment.capture", 1); err != nil {
		t.Fatal(err)
	}
	if err := lim.Allow(ctx, id, "dev", "payment.capture", 1); err == nil {
		t.Fatal("expected exceed")
	}
	if err := lim.Refund(ctx, id, "dev", "payment.capture", 1); err != nil {
		t.Fatal(err)
	}
	if err := lim.Allow(ctx, id, "dev", "payment.capture", 1); err != nil {
		t.Fatalf("refund must restore quota: %v", err)
	}
	// Over-refund floors at zero: one call fits, a second must deny.
	if err := lim.Refund(ctx, id, "dev", "payment.capture", 5); err != nil {
		t.Fatal(err)
	}
	if err := lim.Allow(ctx, id, "dev", "payment.capture", 1); err != nil {
		t.Fatalf("floored refund must allow one call: %v", err)
	}
	if err := lim.Allow(ctx, id, "dev", "payment.capture", 1); err == nil {
		t.Fatal("over-refund must not mint extra quota")
	}
}
