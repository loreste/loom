package risk_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/risk"
)

func TestNilOpFailClosedCritical(t *testing.T) {
	e := risk.NewSimpleEngine()
	got := e.Evaluate(context.Background(), core.Identity{}, nil, &core.Request{})
	if got != core.RiskCritical {
		t.Fatalf("nil op must be critical, got %v", got)
	}
}

func TestNeverLowersBelowOpFloor(t *testing.T) {
	e := risk.NewSimpleEngine()
	op := &core.Operation{Name: "x", Risk: core.RiskHigh}
	got := e.Evaluate(context.Background(), core.Identity{Type: "user"}, op, &core.Request{Boundary: "dev"})
	if got < core.RiskHigh {
		t.Fatalf("must not lower below floor: %v", got)
	}
}

func TestMoneyEffectRaisesToHigh(t *testing.T) {
	e := risk.NewSimpleEngine()
	op := &core.Operation{Name: "pay", Risk: core.RiskLow, Effects: []core.Effect{core.EffectMoney}}
	got := e.Evaluate(context.Background(), core.Identity{}, op, &core.Request{})
	if got < core.RiskHigh {
		t.Fatalf("money ops at least high: %v", got)
	}
}

func TestDeleteInProdIsCritical(t *testing.T) {
	e := risk.NewSimpleEngine()
	op := &core.Operation{Name: "del", Risk: core.RiskLow, Effects: []core.Effect{core.EffectDelete}}
	got := e.Evaluate(context.Background(), core.Identity{}, op, &core.Request{Boundary: "prod"})
	if got != core.RiskCritical {
		t.Fatalf("delete in prod must be critical: %v", got)
	}
}

func TestAgentAndDelegatorRaise(t *testing.T) {
	e := risk.NewSimpleEngine()
	op := &core.Operation{Name: "r", Risk: core.RiskLow}
	base := e.Evaluate(context.Background(), core.Identity{Type: "user"}, op, &core.Request{})
	agent := e.Evaluate(context.Background(), core.Identity{Type: "agent"}, op, &core.Request{})
	if agent <= base {
		t.Fatalf("agent must raise risk: base=%v agent=%v", base, agent)
	}
	del := e.Evaluate(context.Background(), core.Identity{Type: "user", Delegator: "boss"}, op, &core.Request{})
	if del <= base {
		t.Fatalf("delegator must raise risk: base=%v del=%v", base, del)
	}
}

func TestMetadataAndBatchRaise(t *testing.T) {
	e := risk.NewSimpleEngine()
	op := &core.Operation{Name: "r", Risk: core.RiskLow}
	base := e.Evaluate(context.Background(), core.Identity{}, op, &core.Request{})
	md := e.Evaluate(context.Background(), core.Identity{}, op, &core.Request{
		Metadata: map[string]string{"x-danger": "1"},
	})
	if md <= base {
		t.Fatalf("danger metadata must raise")
	}
	batch := e.Evaluate(context.Background(), core.Identity{}, op, &core.Request{
		Input: map[string]any{"count": 500},
	})
	if batch <= base {
		t.Fatalf("large batch must raise")
	}
}

func TestBlockerMaxAllowed(t *testing.T) {
	b := &risk.Blocker{MaxAllowed: core.RiskMedium}
	if msg := b.Check(core.Identity{}, core.RiskHigh); msg == "" {
		t.Fatal("high must block when max is medium")
	}
	if msg := b.Check(core.Identity{}, core.RiskLow); msg != "" {
		t.Fatalf("low must pass: %s", msg)
	}
}

func TestBlockerBreakGlass(t *testing.T) {
	b := &risk.Blocker{MaxAllowed: core.RiskLow, BreakGlassCapability: "break-glass"}
	id := core.Identity{Capabilities: []string{"break-glass"}}
	if msg := b.Check(id, core.RiskCritical); msg != "" {
		t.Fatalf("break-glass must pass: %s", msg)
	}
	if msg := b.Check(core.Identity{}, core.RiskMedium); msg == "" {
		t.Fatal("without break-glass must block")
	}
}

func TestNilBlockerAllows(t *testing.T) {
	var b *risk.Blocker
	if msg := b.Check(core.Identity{}, core.RiskCritical); msg != "" {
		t.Fatal("nil blocker is no-op")
	}
}
