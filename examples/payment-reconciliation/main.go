// Command payment-reconciliation demonstrates payment authorization and the
// safe handling contract for an uncertain durable outcome. Recovery verifies
// provider state and never invokes the payment handler a second time.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/domains/payment"
)

const (
	principal = core.PrincipalID("svc:payments")
	boundary  = core.BoundaryID("merchant-a")
)

func newPaymentApp() (*app.App, string, error) {
	a, err := app.New(app.Config{})
	if err != nil {
		return nil, "", err
	}
	if err := payment.Register(a.Registry); err != nil {
		_ = a.Close()
		return nil, "", err
	}
	token := os.Getenv("LOOM_PAYMENT_TOKEN")
	if token == "" {
		token = "local-payment-token"
	}
	if err := a.AddUser(principal, token, boundary, []string{payment.OpCapture}); err != nil {
		_ = a.Close()
		return nil, "", err
	}
	if err := a.GrantOp(principal, boundary, payment.OpCapture, "payment", "*", []string{"payment_id", "status", "provider_reference", "amount", "currency"}); err != nil {
		_ = a.Close()
		return nil, "", err
	}
	return a, token, nil
}

// providerState is intentionally separate from the Loom response. A provider
// query is reconciliation evidence, not permission to rerun the handler.
type providerState interface {
	CaptureState(context.Context, string) (string, error)
}

func reconcileUnconfirmed(ctx context.Context, response core.Response, provider providerState) (string, error) {
	if response.Outcome != core.OutcomeExecutedUnconfirmed {
		return "not_unconfirmed", nil
	}
	if provider == nil {
		return "queued", fmt.Errorf("payment: provider verifier is not configured")
	}
	reference, _ := response.Output["provider_reference"].(string)
	state, err := provider.CaptureState(ctx, reference)
	if err != nil {
		return "queued", err
	}
	if state == "confirmed" || state == "succeeded" {
		return "reconciled", nil
	}
	return "queued", nil
}

func main() {
	a, token, err := newPaymentApp()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer a.Close()
	if err := a.IssueApproval("payment-approval", principal, payment.OpCapture, boundary, core.RiskHigh, time.Hour); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	response := a.Call(context.Background(), core.Request{
		Operation:      payment.OpCapture,
		Credentials:    core.Credentials{Token: token},
		Boundary:       boundary,
		Resource:       &core.ResourceRef{Type: "payment", ID: "payment-100"},
		Input:          map[string]any{"amount": 25.00, "currency": "USD", "merchant_id": "merchant-a"},
		ApprovalToken:  "payment-approval",
		IdempotencyKey: "payment-demo-1",
	})
	encoded, _ := json.MarshalIndent(response, "", "  ")
	fmt.Println(string(encoded))
	if response.Outcome == core.OutcomeExecutedUnconfirmed {
		fmt.Fprintln(os.Stderr, "payment result is uncertain; enqueue provider reconciliation, never rerun capture")
	}
}
