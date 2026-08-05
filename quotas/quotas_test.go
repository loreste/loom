package quotas_test

import (
	"context"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/quotas"
)

func TestMemoryLimiterAllowUpToLimitDenyBeyond(t *testing.T) {
	lim := quotas.NewMemoryLimiter()
	if err := lim.SetLimit("user:a", "dev", "op.read", 3, time.Minute); err != nil {
		t.Fatal(err)
	}
	id := core.Identity{ID: "user:a"}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := lim.Allow(ctx, id, "dev", "op.read", 1); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if err := lim.Allow(ctx, id, "dev", "op.read", 1); err == nil {
		t.Fatal("expected deny beyond limit")
	}
	// multi-cost consume: 2 remaining-none, a cost-2 call must deny
	if err := lim.Allow(ctx, id, "dev", "op.read", 2); err == nil {
		t.Fatal("cost-2 call at limit must deny")
	}
}

func TestMemoryLimiterScoping(t *testing.T) {
	lim := quotas.NewMemoryLimiter()
	if err := lim.SetLimit("user:a", "dev", "op.read", 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := lim.Allow(ctx, core.Identity{ID: "user:a"}, "dev", "op.read", 1); err != nil {
		t.Fatal(err)
	}
	// different principal unaffected
	if err := lim.Allow(ctx, core.Identity{ID: "user:b"}, "dev", "op.read", 1); err != nil {
		t.Fatalf("other principal must be unaffected: %v", err)
	}
	// different boundary unaffected
	if err := lim.Allow(ctx, core.Identity{ID: "user:a"}, "prod", "op.read", 1); err != nil {
		t.Fatalf("other boundary must be unaffected: %v", err)
	}
	// different operation unaffected
	if err := lim.Allow(ctx, core.Identity{ID: "user:a"}, "dev", "op.write", 1); err != nil {
		t.Fatalf("other operation must be unaffected: %v", err)
	}
	// same principal+boundary+op denied
	if err := lim.Allow(ctx, core.Identity{ID: "user:a"}, "dev", "op.read", 1); err == nil {
		t.Fatal("same key must deny after limit")
	}
}

func TestMemoryLimiterUnconfiguredUnlimited(t *testing.T) {
	lim := quotas.NewMemoryLimiter()
	for i := 0; i < 100; i++ {
		if err := lim.Allow(context.Background(), core.Identity{ID: "user:x"}, "dev", "op.y", 1); err != nil {
			t.Fatalf("unconfigured key must be unlimited: %v", err)
		}
	}
}

func TestMemoryLimiterWindowReset(t *testing.T) {
	lim := quotas.NewMemoryLimiter()
	if err := lim.SetLimit("user:a", "dev", "op.read", 1, 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	id := core.Identity{ID: "user:a"}
	ctx := context.Background()
	if err := lim.Allow(ctx, id, "dev", "op.read", 1); err != nil {
		t.Fatal(err)
	}
	if err := lim.Allow(ctx, id, "dev", "op.read", 1); err == nil {
		t.Fatal("expected deny within window")
	}
	time.Sleep(25 * time.Millisecond)
	if err := lim.Allow(ctx, id, "dev", "op.read", 1); err != nil {
		t.Fatalf("window should have reset: %v", err)
	}
}

func TestMemoryLimiterRefund(t *testing.T) {
	lim := quotas.NewMemoryLimiter()
	if err := lim.SetLimit("user:a", "dev", "op.read", 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	id := core.Identity{ID: "user:a"}
	ctx := context.Background()
	if err := lim.Allow(ctx, id, "dev", "op.read", 1); err != nil {
		t.Fatal(err)
	}
	if err := lim.Allow(ctx, id, "dev", "op.read", 1); err == nil {
		t.Fatal("expected deny at limit")
	}
	// Refund the failed execution's charge; the next call must be allowed.
	if err := lim.Refund(ctx, id, "dev", "op.read", 1); err != nil {
		t.Fatal(err)
	}
	if err := lim.Allow(ctx, id, "dev", "op.read", 1); err != nil {
		t.Fatalf("refund must restore quota: %v", err)
	}
	// Refund floors at zero: over-refunding must not create negative counts.
	if err := lim.Refund(ctx, id, "dev", "op.read", 5); err != nil {
		t.Fatal(err)
	}
	// One call fits the window again (count floored to 0)…
	if err := lim.Allow(ctx, id, "dev", "op.read", 1); err != nil {
		t.Fatalf("floored refund must allow one call: %v", err)
	}
	// …but a second must deny: over-refund must not mint extra quota.
	if err := lim.Allow(ctx, id, "dev", "op.read", 1); err == nil {
		t.Fatal("over-refund must not mint extra quota")
	}
	// Refund of an unconfigured (unlimited) key is a no-op.
	if err := lim.Refund(ctx, id, "dev", "op.other", 1); err != nil {
		t.Fatal(err)
	}
}
