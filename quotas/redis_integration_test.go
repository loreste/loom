package quotas_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/quotas"
)

func TestRedisLimiterIntegrationUsesSharedQuotaState(t *testing.T) {
	redisURL := os.Getenv("LOOM_REDIS_URL")
	if redisURL == "" {
		t.Skip("LOOM_REDIS_URL not set; skip Redis integration")
	}
	client, err := quotas.OpenClient(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	limiter := quotas.NewRedisLimiter(client, quotas.NewConfig())
	principal := core.PrincipalID("redis-integration-" + time.Now().UTC().Format("20060102150405.000000000"))
	boundary := core.BoundaryID("integration")
	operation := "quota.integration"
	if err := limiter.SetLimit(principal, boundary, operation, 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	identity := core.Identity{ID: principal}
	if err := limiter.Allow(context.Background(), identity, boundary, operation, 1); err != nil {
		t.Fatalf("first quota allowance: %v", err)
	}
	if err := limiter.Allow(context.Background(), identity, boundary, operation, 1); err == nil {
		t.Fatal("second quota allowance unexpectedly succeeded")
	}
}
