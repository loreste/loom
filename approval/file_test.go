package approval_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/loreste/loom/approval"
	"github.com/loreste/loom/core"
)

func TestFileEnginePersistAndConsume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")

	e1, err := approval.NewFileEngine(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := e1.Issue("tok-persist-1", "user:bob", "payment.capture", "dev", core.RiskCritical, time.Hour); err != nil {
		t.Fatal(err)
	}

	e2, err := approval.NewFileEngine(path)
	if err != nil {
		t.Fatal(err)
	}
	op := &core.Operation{
		Name:     "payment.capture",
		Risk:     core.RiskHigh,
		Approval: core.ApprovalPolicy{MinRisk: core.RiskHigh},
		Effects:  []core.Effect{core.EffectMoney},
	}
	id := core.Identity{ID: "user:bob"}
	dec := e2.Evaluate(context.Background(), id, op, core.RiskHigh, "dev", "tok-persist-1")
	if !dec.Approved {
		t.Fatalf("expected approved after reload: %+v", dec)
	}
	// Evaluate must NOT consume; only Consume burns the token.
	if err := e2.Consume(context.Background(), id, op, "dev", "tok-persist-1"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	dec = e2.Evaluate(context.Background(), id, op, core.RiskHigh, "dev", "tok-persist-1")
	if dec.Approved {
		t.Fatal("token must be consumed")
	}

	e3, _ := approval.NewFileEngine(path)
	dec = e3.Evaluate(context.Background(), id, op, core.RiskHigh, "dev", "tok-persist-1")
	if dec.Approved {
		t.Fatal("consumed must survive reload")
	}
}

func TestFileEngineNeverStoresRawToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.json")
	e, _ := approval.NewFileEngine(path)
	raw := "super-secret-approval-token-xyz"
	_ = e.Issue(raw, "user:bob", "payment.capture", "dev", core.RiskCritical, time.Hour)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), raw) {
		t.Fatal("raw token must not appear on disk")
	}
}
