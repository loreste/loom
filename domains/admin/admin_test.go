package admin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/domains/admin"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/runtime"
)

func setup(t *testing.T) *runtime.TestStack {
	t.Helper()
	s, err := runtime.NewTestStack()
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Register(s.Registry, admin.Deps{Approvals: s.Approval, Registry: s.Registry}); err != nil {
		t.Fatal(err)
	}
	// A normal operation the caller can see, and one they cannot.
	s.Registry.MustRegister(&core.Operation{
		Name:        "document.read",
		Description: "read a document",
		Permissions: []string{"document.read"},
		Risk:        core.RiskLow,
		Effects:     []core.Effect{core.EffectRead},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return &core.Result{Output: map[string]any{}}, nil
	})
	s.Registry.MustRegister(&core.Operation{
		Name:        "payment.capture",
		Description: "capture money",
		Permissions: []string{"payment.capture"},
		Risk:        core.RiskHigh,
		Effects:     []core.Effect{core.EffectMoney},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return &core.Result{Output: map[string]any{}}, nil
	})

	if err := s.Verifier.Register(identity.StaticPrincipal{
		ID: "user:agent", Type: "agent", Boundary: "dev", Token: "agent-token",
		Capabilities: []string{"catalog.spec", "document.read"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Boundary.Grant("user:agent", "dev"); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{admin.OpCatalogSpec, "document.read"} {
		if err := s.Policy.AddRule(policy.Rule{
			Principal: "user:agent", Boundary: "dev", Operation: op, Priority: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Fields.GrantFields("user:agent", "dev", admin.OpCatalogSpec, []string{"*"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func callSpec(t *testing.T, s *runtime.TestStack, token string) core.Response {
	t.Helper()
	return s.Runtime.Execute(context.Background(), core.Request{
		Operation:   admin.OpCatalogSpec,
		Credentials: core.Credentials{Scheme: "bearer", Token: token},
		Boundary:    "dev",
	})
}

func toolNames(t *testing.T, resp core.Response) []string {
	t.Helper()
	raw, ok := resp.Output["tools"].([]any)
	if !ok {
		t.Fatalf("tools missing or wrong type: %#v", resp.Output["tools"])
	}
	names := make([]string, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("tool entry wrong type: %#v", item)
		}
		names = append(names, m["name"].(string))
	}
	return names
}

func TestCatalogSpecFilteredByCapabilities(t *testing.T) {
	s := setup(t)
	resp := callSpec(t, s, "agent-token")
	if !resp.Allowed {
		t.Fatalf("denied: %+v", resp.Denial)
	}
	names := toolNames(t, resp)
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	// Caller holds catalog.spec + document.read only.
	if !seen["document.read"] || !seen[admin.OpCatalogSpec] {
		t.Fatalf("expected document.read and catalog.spec, got %v", names)
	}
	// Adversarial: payment.capture and catalog.list must not leak.
	if seen["payment.capture"] || seen[admin.OpCatalogList] {
		t.Fatalf("spec leaked ungranted operations: %v", names)
	}
	// approval.issue requires capability the caller lacks — hidden.
	if seen[admin.OpApprovalIssue] {
		t.Fatalf("spec leaked approval.issue: %v", names)
	}
}

func TestCatalogSpecNoCapabilitiesSeesNothing(t *testing.T) {
	s, err := runtime.NewTestStack()
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Register(s.Registry, admin.Deps{Approvals: s.Approval, Registry: s.Registry}); err != nil {
		t.Fatal(err)
	}
	// Principal may invoke catalog.spec but holds no other capability.
	if err := s.Verifier.Register(identity.StaticPrincipal{
		ID: "user:empty", Type: "agent", Boundary: "dev", Token: "empty-token",
		Capabilities: []string{"catalog.spec"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Boundary.Grant("user:empty", "dev"); err != nil {
		t.Fatal(err)
	}
	if err := s.Policy.AddRule(policy.Rule{
		Principal: "user:empty", Boundary: "dev", Operation: admin.OpCatalogSpec, Priority: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Fields.GrantFields("user:empty", "dev", admin.OpCatalogSpec, []string{"*"}); err != nil {
		t.Fatal(err)
	}
	resp := callSpec(t, s, "empty-token")
	if !resp.Allowed {
		t.Fatalf("denied: %+v", resp.Denial)
	}
	names := toolNames(t, resp)
	// Only catalog.spec itself is visible — no other operation leaks.
	if len(names) != 1 || names[0] != admin.OpCatalogSpec {
		t.Fatalf("capability-less caller must see only catalog.spec, got %v", names)
	}
}

func TestCatalogSpecNeverContainsSensitiveFieldNames(t *testing.T) {
	s := setup(t)
	s.Registry.MustRegister(&core.Operation{
		Name:            "document.read.secret",
		Description:     "has secret fields",
		Permissions:     []string{"document.read"},
		Risk:            core.RiskLow,
		SensitiveFields: []string{"ssn"},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return &core.Result{Output: map[string]any{}}, nil
	})
	resp := callSpec(t, s, "agent-token")
	if !resp.Allowed {
		t.Fatalf("denied: %+v", resp.Denial)
	}
	var found bool
	for _, item := range resp.Output["tools"].([]any) {
		m := item.(map[string]any)
		if m["name"] == "document.read.secret" {
			found = true
			if m["sensitive_fields_present"] != true {
				t.Fatalf("presence flag missing: %#v", m)
			}
		}
	}
	if !found {
		t.Fatal("document.read.secret spec missing")
	}
	// Adversarial: the sensitive field NAME must not appear anywhere in output.
	blob, _ := json.Marshal(resp.Output)
	if strings.Contains(string(blob), "ssn") {
		t.Fatalf("sensitive field name leaked: %s", blob)
	}
}
