package approval_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/loreste/loom/approval"
	"github.com/loreste/loom/core"
)

func approvalOp() *core.Operation {
	return &core.Operation{
		Name:     "payment.capture",
		Risk:     core.RiskHigh,
		Approval: core.ApprovalPolicy{MinRisk: core.RiskHigh},
		Effects:  []core.Effect{core.EffectMoney},
	}
}

// A token issued for boundary "dev" must be rejected in "prod" (memory engine).
func TestMemoryEngineBoundaryMismatch(t *testing.T) {
	e := approval.NewMemoryEngine()
	if err := e.Issue("tok-dev", "user:bob", "payment.capture", "dev", core.RiskCritical, time.Hour); err != nil {
		t.Fatal(err)
	}
	id := core.Identity{ID: "user:bob"}
	op := approvalOp()
	if dec := e.Evaluate(context.Background(), id, op, core.RiskHigh, "prod", "tok-dev"); dec.Approved {
		t.Fatal("dev token must not approve in prod")
	}
	if dec := e.Evaluate(context.Background(), id, op, core.RiskHigh, "dev", "tok-dev"); !dec.Approved {
		t.Fatal("dev token must approve in dev")
	}
}

// Evaluate must never consume; only Consume burns a single-use token.
func TestMemoryEngineEvaluateDoesNotConsume(t *testing.T) {
	e := approval.NewMemoryEngine()
	if err := e.Issue("tok-x", "user:bob", "payment.capture", "dev", core.RiskCritical, time.Hour); err != nil {
		t.Fatal(err)
	}
	id := core.Identity{ID: "user:bob"}
	op := approvalOp()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if dec := e.Evaluate(ctx, id, op, core.RiskHigh, "dev", "tok-x"); !dec.Approved {
			t.Fatalf("evaluate %d must approve without consuming: %+v", i, dec)
		}
	}
	if err := e.Consume(ctx, id, op, "dev", "tok-x"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if dec := e.Evaluate(ctx, id, op, core.RiskHigh, "dev", "tok-x"); dec.Approved {
		t.Fatal("token must be consumed after Consume")
	}
	if err := e.Consume(ctx, id, op, "dev", "tok-x"); err == nil {
		t.Fatal("second Consume must fail (single-use)")
	}
}

// Consume must enforce the same boundary binding as Evaluate.
func TestMemoryEngineConsumeBoundaryMismatch(t *testing.T) {
	e := approval.NewMemoryEngine()
	if err := e.Issue("tok-cb", "user:bob", "payment.capture", "dev", core.RiskCritical, time.Hour); err != nil {
		t.Fatal(err)
	}
	id := core.Identity{ID: "user:bob"}
	op := approvalOp()
	ctx := context.Background()
	if err := e.Consume(ctx, id, op, "prod", "tok-cb"); err == nil {
		t.Fatal("consume in wrong boundary must fail")
	}
	// Failed consume must leave the token usable.
	if err := e.Consume(ctx, id, op, "dev", "tok-cb"); err != nil {
		t.Fatalf("token must remain consumable after failed consume: %v", err)
	}
}

// Boundary binding must hold for the file engine too (persisted records).
func TestFileEngineBoundaryMismatch(t *testing.T) {
	dir := t.TempDir()
	e, err := approval.NewFileEngine(filepath.Join(dir, "approvals.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Issue("tok-fdev", "user:bob", "payment.capture", "dev", core.RiskCritical, time.Hour); err != nil {
		t.Fatal(err)
	}
	id := core.Identity{ID: "user:bob"}
	op := approvalOp()
	ctx := context.Background()
	if dec := e.Evaluate(ctx, id, op, core.RiskHigh, "prod", "tok-fdev"); dec.Approved {
		t.Fatal("dev token must not approve in prod (file engine)")
	}
	if err := e.Consume(ctx, id, op, "prod", "tok-fdev"); err == nil {
		t.Fatal("consume in wrong boundary must fail (file engine)")
	}
	if dec := e.Evaluate(ctx, id, op, core.RiskHigh, "dev", "tok-fdev"); !dec.Approved {
		t.Fatal("dev token must still approve in dev")
	}
}

func TestMemoryEngineBindsApprovalToOperationVersion(t *testing.T) {
	e := approval.NewMemoryEngine()
	if err := e.IssueVersioned("tok-v2", "user:bob", "payment.capture", "2", "dev", core.RiskCritical, time.Hour); err != nil {
		t.Fatal(err)
	}
	id := core.Identity{ID: "user:bob"}
	opV1 := approvalOp()
	opV2 := *opV1
	opV2.Version = "2"
	if dec := e.Evaluate(context.Background(), id, opV1, core.RiskHigh, "dev", "tok-v2"); dec.Approved {
		t.Fatal("v2 approval must not authorize v1 operation")
	}
	if dec := e.Evaluate(context.Background(), id, &opV2, core.RiskHigh, "dev", "tok-v2"); !dec.Approved {
		t.Fatalf("v2 approval should authorize v2 operation: %+v", dec)
	}
}
