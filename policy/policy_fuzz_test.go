package policy_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/policy"
)

func FuzzCheckOperationPermission(f *testing.F) {
	eng := policy.NewMemoryEngine()
	_ = eng.AddRule(policy.Rule{
		Principal: "user:a",
		Operation: "op.x",
		Priority:  1,
	})
	f.Add("user:a", "op.x", "cap1")
	f.Add("user:b", "op.x", "")
	f.Add("", "", "")
	f.Add("user:a", "op.y", "cap1")

	f.Fuzz(func(t *testing.T, principal, opName, cap string) {
		id := core.Identity{ID: core.PrincipalID(principal)}
		if cap != "" {
			id.Capabilities = []string{cap}
		}
		op := &core.Operation{Name: opName, Permissions: nil}
		if cap != "" {
			op.Permissions = []string{cap}
		}
		dec := eng.CheckOperationPermission(context.Background(), id, op)
		// Never allow unknown principals/ops without rule
		if dec.Decision.Allowed() {
			if principal != "user:a" || opName != "op.x" {
				t.Fatalf("unexpected allow for %s %s", principal, opName)
			}
		}
		// Eval never panics; deny is always structured
		if dec.Decision != core.DecisionAllow && dec.Decision != core.DecisionDeny {
			t.Fatalf("bad decision %v", dec.Decision)
		}
	})
}
