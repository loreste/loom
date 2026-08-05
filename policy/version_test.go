package policy_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/policy"
)

func TestOperationPolicyCanBindExactVersion(t *testing.T) {
	engine := policy.NewMemoryEngine()
	if err := engine.AddRule(policy.Rule{
		Principal:        "alice",
		Operation:        "document.read",
		OperationVersion: "2",
		Priority:         1,
	}); err != nil {
		t.Fatal(err)
	}
	req := &core.Request{Operation: "document.read"}
	opV1 := &core.Operation{Name: "document.read", Version: "1"}
	opV2 := &core.Operation{Name: "document.read", Version: "2"}
	if got := engine.EvaluateContextual(context.Background(), core.Identity{ID: "alice"}, "dev", opV1, req); got.Decision.Allowed() {
		t.Fatal("version 2 policy must not authorize version 1")
	}
	if got := engine.EvaluateContextual(context.Background(), core.Identity{ID: "alice"}, "dev", opV2, req); !got.Decision.Allowed() {
		t.Fatalf("version 2 policy should authorize version 2: %+v", got)
	}
}
