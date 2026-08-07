package main

import (
	"context"
	"testing"
	"time"

	"github.com/loreste/loom/core"
)

func TestTelecomTenantBoundaryAndVersionIsolation(t *testing.T) {
	p, err := newTelecomPlatform("telecom-test-token")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	response := execute(context.Background(), p, "telecom-test-token", "telecom.sip_trunk.create", &core.ResourceRef{Type: "sip_trunk", ID: "trunk-1"}, map[string]any{"customer_id": "customer-1"}, "")
	if !response.Allowed {
		t.Fatalf("valid tenant call denied: allowed=%v", response.Allowed)
	}
	wrongBoundary := p.Runtime.Execute(context.Background(), core.Request{
		Operation: "telecom.sip_trunk.create", OperationVersion: "1", Credentials: core.Credentials{Scheme: "bearer", Token: "telecom-test-token"},
		Boundary: "tenant-b", Resource: &core.ResourceRef{Type: "sip_trunk", ID: "trunk-1"}, Input: map[string]any{"customer_id": "customer-1"}, IdempotencyKey: "wrong-boundary",
	})
	if wrongBoundary.Allowed {
		t.Fatalf("cross-tenant call allowed: response=%+v", wrongBoundary)
	}
	unknownVersion := p.Runtime.Execute(context.Background(), core.Request{
		Operation: "telecom.sip_trunk.create", OperationVersion: "2", Credentials: core.Credentials{Scheme: "bearer", Token: "telecom-test-token"},
		Boundary: boundary, Resource: &core.ResourceRef{Type: "sip_trunk", ID: "trunk-2"}, Input: map[string]any{"customer_id": "customer-1"}, IdempotencyKey: "unknown-version",
	})
	if unknownVersion.Allowed {
		t.Fatalf("unknown operation version allowed: response=%+v", unknownVersion)
	}
}

func TestTelecomHighRiskRequiresApprovalAndIsSingleUse(t *testing.T) {
	p, err := newTelecomPlatform("telecom-approval-token")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	withoutApproval := execute(context.Background(), p, "telecom-approval-token", "telecom.credit.change", &core.ResourceRef{Type: "credit_account", ID: "acct-1"}, map[string]any{"delta": "10.00", "amount": "10.00", "currency": "USD"}, "")
	if withoutApproval.Allowed || withoutApproval.Denial == nil || withoutApproval.Denial.Reason != core.ReasonApprovalRequired {
		t.Fatalf("credit change without approval: response=%+v", withoutApproval)
	}
	approval := "single-use-telecom-approval"
	if err := p.IssueApproval(approval, operatorID, "telecom.credit.change", boundary, core.RiskCritical, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	approved := execute(context.Background(), p, "telecom-approval-token", "telecom.credit.change", &core.ResourceRef{Type: "credit_account", ID: "acct-1"}, map[string]any{"delta": "10.00", "amount": "10.00", "currency": "USD"}, approval)
	if !approved.Allowed {
		t.Fatalf("approved credit change denied: response=%+v", approved)
	}
	replay := execute(context.Background(), p, "telecom-approval-token", "telecom.credit.change", &core.ResourceRef{Type: "credit_account", ID: "acct-2"}, map[string]any{"delta": "10.00", "amount": "10.00", "currency": "USD"}, approval)
	if replay.Allowed {
		t.Fatalf("approval replay allowed: response=%+v", replay)
	}
}
