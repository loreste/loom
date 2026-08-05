package payment_test

import (
	"context"
	"testing"
	"time"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/domains/payment"
)

func setupPay(t *testing.T) *app.App {
	t.Helper()
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := payment.Register(a.Registry); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPaymentCaptureRequiresApprovalAndIdempotency(t *testing.T) {
	a := setupPay(t)
	_ = a.AddUser("bob", "bob-tok", "dev", []string{"payment.capture"})
	_ = a.GrantOp("bob", "dev", "payment.capture", "payment", "*",
		[]string{"payment_id", "status", "amount", "currency", "merchant_id"})

	ctx := context.Background()
	// Missing idempotency + approval
	resp := a.Call(ctx, core.Request{
		Operation:   "payment.capture",
		Credentials: core.Credentials{Token: "bob-tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "payment", ID: "*"},
		Input: map[string]any{
			"amount": 10.0, "currency": "USD", "merchant_id": "m1",
		},
	})
	if resp.Allowed {
		t.Fatal("must require idempotency/approval")
	}

	// With idempotency but no approval → approval_required
	resp = a.Call(ctx, core.Request{
		Operation:   "payment.capture",
		Credentials: core.Credentials{Token: "bob-tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "payment", ID: "*"},
		Input: map[string]any{
			"amount": 10.0, "currency": "USD", "merchant_id": "m1",
		},
		IdempotencyKey: "pay-1",
	})
	if resp.Allowed {
		t.Fatal("high-risk money op must need approval")
	}
	if resp.Denial == nil || resp.Denial.Reason != core.ReasonApprovalRequired {
		t.Fatalf("want approval_required, got %+v", resp.Denial)
	}
	if !resp.Denial.Retryable || resp.Denial.Hint == "" {
		t.Fatalf("agent-actionable denial missing: %+v", resp.Denial)
	}

	// Issue approval and capture
	if err := a.IssueApproval("apr-1", "bob", "payment.capture", "dev", core.RiskCritical, time.Hour); err != nil {
		t.Fatal(err)
	}
	resp = a.Call(ctx, core.Request{
		Operation:   "payment.capture",
		Credentials: core.Credentials{Token: "bob-tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "payment", ID: "*"},
		Input: map[string]any{
			"amount": 10.0, "currency": "USD", "merchant_id": "m1",
		},
		IdempotencyKey: "pay-2",
		ApprovalToken:  "apr-1",
	})
	if !resp.Allowed {
		t.Fatalf("capture: %+v", resp.Denial)
	}
	if resp.Output["status"] != "captured" {
		t.Fatalf("output=%v", resp.Output)
	}
	// Sensitive processor payload stripped
	if _, ok := resp.Output["raw_processor_payload"]; ok {
		t.Fatal("raw_processor_payload must not leak")
	}
	if _, ok := resp.Output["pan"]; ok {
		t.Fatal("pan must not leak")
	}
}

func TestPaymentRefundAlwaysNeedsApproval(t *testing.T) {
	a := setupPay(t)
	_ = a.AddUser("bob", "bob-tok", "dev", []string{"payment.refund"})
	_ = a.GrantOp("bob", "dev", "payment.refund", "payment", "*",
		[]string{"refund_id", "payment_id", "status", "amount"})

	resp := a.Call(context.Background(), core.Request{
		Operation:   "payment.refund",
		Credentials: core.Credentials{Token: "bob-tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "payment", ID: "p1"},
		Input: map[string]any{
			"amount": 1.0, "currency": "USD", "payment_id": "p1",
		},
		IdempotencyKey: "ref-1",
	})
	if resp.Allowed || resp.Denial == nil || resp.Denial.Reason != core.ReasonApprovalRequired {
		t.Fatalf("refund must require approval: %+v", resp.Denial)
	}
}

func TestPaymentCaptureDeniedWithoutCapability(t *testing.T) {
	a := setupPay(t)
	_ = a.AddUser("alice", "a-tok", "dev", []string{"document.read"}) // no payment
	resp := a.Call(context.Background(), core.Request{
		Operation:   "payment.capture",
		Credentials: core.Credentials{Token: "a-tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "payment", ID: "*"},
		Input: map[string]any{
			"amount": 1.0, "currency": "USD", "merchant_id": "m",
		},
		IdempotencyKey: "x",
	})
	if resp.Allowed {
		t.Fatal("no payment cap must deny")
	}
}
