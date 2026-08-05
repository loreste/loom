package bootstrap_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/internal/testtokens"
)

func TestGovernedApprovalIssue(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}

	// Bob cannot issue approvals
	resp := p.Runtime.Execute(context.Background(), core.Request{
		Operation:   "approval.issue",
		Credentials: core.Credentials{Token: "bob-finance-token"},
		Boundary:    "dev",
		Input: map[string]any{
			"principal":      "user:bob",
			"operation":      "payment.capture",
			"boundary":       "dev",
			"generate_token": true,
		},
		IdempotencyKey: "iss-bob-1",
	})
	if resp.Allowed {
		t.Fatal("bob must not issue approvals")
	}

	// Approver can issue
	resp = p.Runtime.Execute(context.Background(), core.Request{
		Operation:   "approval.issue",
		Credentials: core.Credentials{Token: "approver-admin-token"},
		Boundary:    "dev",
		Input: map[string]any{
			"principal":      "user:bob",
			"operation":      "payment.capture",
			"boundary":       "dev",
			"generate_token": true,
			"ttl_seconds":    float64(3600),
		},
		IdempotencyKey: "iss-appr-1",
	})
	if !resp.Allowed {
		t.Fatalf("approver issue failed: %+v", resp.Denial)
	}
	tok, _ := resp.Output["token"].(string)
	if tok == "" {
		t.Fatal("token missing from output")
	}

	// Bob uses issued token for payment
	pay := p.Runtime.Execute(context.Background(), core.Request{
		Operation:   "payment.capture",
		Credentials: core.Credentials{Token: "bob-finance-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "payment", ID: "p1"},
		Input: map[string]any{
			"amount": 12.0, "currency": "USD", "merchant_id": "m1",
		},
		IdempotencyKey: "pay-1",
		ApprovalToken:  tok,
	})
	if !pay.Allowed {
		t.Fatalf("payment: %+v", pay.Denial)
	}
}

func TestCannotIssueApprovalForApprovalIssue(t *testing.T) {
	p, _ := bootstrap.NewPlatform(bootstrap.Config{DemoTokens: testtokens.Demo()})
	resp := p.Runtime.Execute(context.Background(), core.Request{
		Operation:   "approval.issue",
		Credentials: core.Credentials{Token: "approver-admin-token"},
		Boundary:    "dev",
		Input: map[string]any{
			"principal": "user:alice",
			"operation": "approval.issue",
			"boundary":  "dev",
			"token":     "nested-appr-token",
		},
		IdempotencyKey: "iss-nested",
	})
	if resp.Allowed {
		t.Fatal("recursive approval.issue must fail")
	}
}

func TestCatalogListGoverned(t *testing.T) {
	p, _ := bootstrap.NewPlatform(bootstrap.Config{DemoTokens: testtokens.Demo()})
	// alice cannot list
	resp := p.Runtime.Execute(context.Background(), core.Request{
		Operation:   "catalog.list",
		Credentials: core.Credentials{Token: "alice-secret-token"},
		Boundary:    "dev",
		Input:       map[string]any{},
	})
	if resp.Allowed {
		t.Fatal("alice must not list catalog")
	}
	resp = p.Runtime.Execute(context.Background(), core.Request{
		Operation:   "catalog.list",
		Credentials: core.Credentials{Token: "approver-admin-token"},
		Boundary:    "dev",
		Input:       map[string]any{},
	})
	if !resp.Allowed {
		t.Fatalf("%+v", resp.Denial)
	}
	if resp.Output["count"] == nil {
		t.Fatal("expected count")
	}
}

func TestDataDirStickyApprovals(t *testing.T) {
	dir := t.TempDir()
	p1, err := bootstrap.NewPlatform(bootstrap.Config{DataDir: dir, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	if err := p1.IssueApproval("sticky-tok", "user:bob", "payment.capture", "dev", core.RiskCritical, time.Hour); err != nil {
		t.Fatal(err)
	}

	// New process simulation
	p2, err := bootstrap.NewPlatform(bootstrap.Config{DataDir: dir, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	resp := p2.Runtime.Execute(context.Background(), core.Request{
		Operation:   "payment.capture",
		Credentials: core.Credentials{Token: "bob-finance-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "payment", ID: "p2"},
		Input: map[string]any{
			"amount": 5.0, "currency": "USD", "merchant_id": "m",
		},
		IdempotencyKey: "sticky-pay",
		ApprovalToken:  "sticky-tok",
	})
	if !resp.Allowed {
		t.Fatalf("sticky approval failed: %+v", resp.Denial)
	}

	// idempotency sticky
	resp2 := p2.Runtime.Execute(context.Background(), core.Request{
		Operation:   "payment.capture",
		Credentials: core.Credentials{Token: "bob-finance-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "payment", ID: "p2"},
		Input: map[string]any{
			"amount": 5.0, "currency": "USD", "merchant_id": "m",
		},
		IdempotencyKey: "sticky-pay",
		ApprovalToken:  "unused",
	})
	if !resp2.Allowed || !resp2.IdempotentReplay {
		// reload p3 for true disk idempotency
		p3, _ := bootstrap.NewPlatform(bootstrap.Config{DataDir: dir, DemoTokens: testtokens.Demo()})
		resp3 := p3.Runtime.Execute(context.Background(), core.Request{
			Operation:   "payment.capture",
			Credentials: core.Credentials{Token: "bob-finance-token"},
			Boundary:    "dev",
			Resource:    &core.ResourceRef{Type: "payment", ID: "p2"},
			Input: map[string]any{
				"amount": 5.0, "currency": "USD", "merchant_id": "m",
			},
			IdempotencyKey: "sticky-pay",
		})
		if !resp3.Allowed || !resp3.IdempotentReplay {
			t.Fatalf("idempotency not sticky: allowed=%v replay=%v denial=%+v (same proc replay=%v)",
				resp3.Allowed, resp3.IdempotentReplay, resp3.Denial, resp2.IdempotentReplay)
		}
	}

	// ensure data files exist
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatalf("expected at least one .json data file in %s", dir)
	}
}
