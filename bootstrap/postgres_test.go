package bootstrap_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/internal/testtokens"
)

func TestPlatformPostgresEndToEnd(t *testing.T) {
	dsn := os.Getenv("LOOM_DATABASE_URL")
	if dsn == "" {
		t.Skip("LOOM_DATABASE_URL not set")
	}
	p, err := bootstrap.NewPlatform(bootstrap.Config{DatabaseURL: dsn, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if p.Ready == nil {
		t.Fatal("Ready should be set for postgres")
	}
	if err := p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The approval token must be unique per run: reissuing a token that is
	// already stored fails, so a fixed value only works against a database
	// that is recreated between runs.
	approvalToken := "pg-plat-appr-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	// Approver issues via governed op
	iss := p.Runtime.Execute(context.Background(), core.Request{
		Operation:   "approval.issue",
		Credentials: core.Credentials{Token: "approver-admin-token"},
		Boundary:    "dev",
		Input: map[string]any{
			"principal": "user:bob",
			"operation": "payment.capture",
			"boundary":  "dev",
			"token":     approvalToken,
		},
		IdempotencyKey: "pg-iss-" + strconv.FormatInt(time.Now().UnixNano(), 10),
	})
	if !iss.Allowed {
		t.Fatalf("issue: %+v", iss.Denial)
	}

	// New platform instance (simulates other process) shares DB
	p2, err := bootstrap.NewPlatform(bootstrap.Config{DatabaseURL: dsn, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p2.Close() })

	pay := p2.Runtime.Execute(context.Background(), core.Request{
		Operation:   "payment.capture",
		Credentials: core.Credentials{Token: "bob-finance-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "payment", ID: "pg1"},
		Input: map[string]any{
			"amount": 7.0, "currency": "USD", "merchant_id": "m",
		},
		IdempotencyKey: "pg-pay-1",
		ApprovalToken:  approvalToken,
	})
	if !pay.Allowed {
		t.Fatalf("pay: %+v", pay.Denial)
	}

	// Replay on yet another instance
	p3, err := bootstrap.NewPlatform(bootstrap.Config{DatabaseURL: dsn, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p3.Close() })
	replay := p3.Runtime.Execute(context.Background(), core.Request{
		Operation:   "payment.capture",
		Credentials: core.Credentials{Token: "bob-finance-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "payment", ID: "pg1"},
		Input: map[string]any{
			"amount": 7.0, "currency": "USD", "merchant_id": "m",
		},
		IdempotencyKey: "pg-pay-1",
	})
	if !replay.Allowed || !replay.IdempotentReplay {
		t.Fatalf("replay: allowed=%v replay=%v denial=%+v", replay.Allowed, replay.IdempotentReplay, replay.Denial)
	}
}
