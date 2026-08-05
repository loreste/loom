package tenancy_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/tenancy"
)

func TestAppTenantResolverUsesOneBoundaryForAllGatesAndAudit(t *testing.T) {
	verifier := identity.NewMemoryVerifier()
	if err := verifier.Register(identity.StaticPrincipal{
		ID:         "user:tenant-a",
		Type:       "user",
		Token:      "tenant-a-token",
		Attributes: map[string]string{"tenant_id": "tenant-a"},
		Capabilities: []string{
			"tenant.read",
		},
	}); err != nil {
		t.Fatal(err)
	}
	resolver, err := tenancy.NewResolver("tenant_id")
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.New(app.Config{
		IdentityVerifier: verifier,
		TenantResolver:   resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Register(&core.Operation{
		Name:        "tenant.read",
		Permissions: []string{"tenant.read"},
	}, func(*core.ExecutionContext) (*core.Result, error) {
		return &core.Result{Output: map[string]any{"value": "tenant-a"}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.GrantBoundary("user:tenant-a", "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := a.AllowPolicy(policy.Rule{Principal: "user:tenant-a", Boundary: "tenant-a", Operation: "tenant.read", Priority: 10}); err != nil {
		t.Fatal(err)
	}
	if err := a.AllowFields("user:tenant-a", "tenant-a", "tenant.read", []string{"value"}); err != nil {
		t.Fatal(err)
	}

	ok := a.Call(context.Background(), core.Request{
		Operation:   "tenant.read",
		Credentials: core.Credentials{Token: "tenant-a-token"},
		Boundary:    "tenant-a",
	})
	if !ok.Allowed {
		t.Fatalf("same tenant denied: %+v", ok.Denial)
	}
	if got := ok.Output["value"]; got != "tenant-a" {
		t.Fatalf("unexpected output: %#v", got)
	}

	cross := a.Call(context.Background(), core.Request{
		Operation:   "tenant.read",
		Credentials: core.Credentials{Token: "tenant-a-token"},
		Boundary:    "tenant-b",
	})
	if cross.Allowed || cross.Denial == nil || cross.Denial.Reason != core.ReasonBoundaryViolation {
		t.Fatalf("cross-tenant request was not denied: %+v", cross)
	}
	events := a.AuditSink.Snapshot()
	if len(events) < 2 || events[0].TenantID == "" || events[1].TenantID == "" {
		t.Fatalf("audit events missing tenant context: %+v", events)
	}
}
