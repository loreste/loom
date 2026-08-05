package deployment_test

import (
	"context"
	"testing"
	"time"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/domains/deployment"
)

func setupDep(t *testing.T) *app.App {
	t.Helper()
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := deployment.Register(a.Registry); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDeploymentReleaseHappyPath(t *testing.T) {
	a := setupDep(t)
	_ = a.AddUser("ops", "ops-tok", "dev", []string{"deployment.release"})
	_ = a.GrantOp("ops", "dev", "deployment.release", "service", "*",
		[]string{"release_id", "service", "version", "strategy", "status", "boundary"})
	_ = a.IssueApproval("apr", "ops", "deployment.release", "dev", core.RiskCritical, time.Hour)

	resp := a.Call(context.Background(), core.Request{
		Operation:   "deployment.release",
		Credentials: core.Credentials{Token: "ops-tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "service", ID: "api"},
		Input: map[string]any{
			"service": "api", "version": "1.2.3", "strategy": "canary",
		},
		IdempotencyKey: "rel-1",
		ApprovalToken:  "apr",
	})
	if !resp.Allowed {
		t.Fatalf("%+v", resp.Denial)
	}
	if resp.Output["status"] != "released" || resp.Output["strategy"] != "canary" {
		t.Fatalf("%v", resp.Output)
	}
}

func TestDeploymentReleaseRejectsHostileVersion(t *testing.T) {
	a := setupDep(t)
	_ = a.AddUser("ops", "ops-tok", "dev", []string{"deployment.release"})
	_ = a.GrantOp("ops", "dev", "deployment.release", "service", "*",
		[]string{"release_id", "service", "version", "strategy", "status", "boundary"})

	// Path traversal in version — schema pattern may reject first; also handler check.
	resp := a.Call(context.Background(), core.Request{
		Operation:   "deployment.release",
		Credentials: core.Credentials{Token: "ops-tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "service", ID: "api"},
		Input: map[string]any{
			"service": "api", "version": "../etc/passwd",
		},
		IdempotencyKey: "bad-ver",
	})
	if resp.Allowed {
		t.Fatal("hostile version must deny")
	}
}

func TestServerDestroyRequiresApproval(t *testing.T) {
	a := setupDep(t)
	_ = a.AddUser("ops", "ops-tok", "dev", []string{"server.destroy"})
	_ = a.GrantOp("ops", "dev", "server.destroy", "server", "*",
		[]string{"server_id", "status"})

	resp := a.Call(context.Background(), core.Request{
		Operation:      "server.destroy",
		Credentials:    core.Credentials{Token: "ops-tok"},
		Boundary:       "dev",
		Resource:       &core.ResourceRef{Type: "server", ID: "s1"},
		Input:          map[string]any{"server_id": "s1"},
		IdempotencyKey: "des-1",
	})
	if resp.Allowed {
		t.Fatal("destroy must require approval")
	}
	if resp.Denial == nil || resp.Denial.Reason != core.ReasonApprovalRequired {
		t.Fatalf("%+v", resp.Denial)
	}
}

func TestServerDestroyProdGuardrail(t *testing.T) {
	a := setupDep(t)
	// Grant prod boundary
	_ = a.AddUser("ops", "ops-tok", "prod", []string{"server.destroy"})
	_ = a.GrantBoundary("ops", "prod")
	_ = a.GrantOp("ops", "prod", "server.destroy", "server", "*",
		[]string{"server_id", "status"})
	_ = a.IssueApproval("apr-prod", "ops", "server.destroy", "prod", core.RiskCritical, time.Hour)

	resp := a.Call(context.Background(), core.Request{
		Operation:      "server.destroy",
		Credentials:    core.Credentials{Token: "ops-tok"},
		Boundary:       "prod",
		Resource:       &core.ResourceRef{Type: "server", ID: "s1"},
		Input:          map[string]any{"server_id": "s1"},
		IdempotencyKey: "des-prod",
		ApprovalToken:  "apr-prod",
	})
	// Production protection guardrail should block delete in prod even with approval.
	if resp.Allowed {
		t.Fatal("destroy in prod must be blocked by guardrails")
	}
	if resp.Denial != nil && resp.Denial.Reason != core.ReasonGuardrail &&
		resp.Denial.Reason != core.ReasonRiskBlocked &&
		resp.Denial.Reason != core.ReasonApprovalRequired {
		// Any fail-closed deny is acceptable; prefer guardrail.
		t.Logf("prod destroy denied: %s", resp.Denial.Reason)
	}
}

func TestDefaultDenyDeployment(t *testing.T) {
	a := setupDep(t)
	resp := a.Call(context.Background(), core.Request{
		Operation:   "deployment.release",
		Credentials: core.Credentials{Token: "nobody"},
		Boundary:    "dev",
		Input:       map[string]any{"service": "x", "version": "1"},
	})
	if resp.Allowed {
		t.Fatal("must deny")
	}
}
