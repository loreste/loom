package core_test

import (
	"testing"

	"github.com/loreste/loom/core"
)

func TestRegistryDenyUnknown(t *testing.T) {
	r := core.NewRegistry()
	if _, err := r.Get("x"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestRegistryNoOverwrite(t *testing.T) {
	r := core.NewRegistry()
	op := &core.Operation{Name: "a.b"}
	h := func(ec *core.ExecutionContext) (*core.Result, error) { return nil, nil }
	if err := r.Register(op, h); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(op, h); err == nil {
		t.Fatal("overwrite must fail")
	}
}

func TestRegistryBindsExactOperationVersion(t *testing.T) {
	r := core.NewRegistry()
	if err := r.Register(&core.Operation{Name: "invoice.read", Version: "2"}, func(*core.ExecutionContext) (*core.Result, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetVersion("invoice.read", "1"); err == nil {
		t.Fatal("mismatched operation version must be rejected")
	}
	op, err := r.GetVersion("invoice.read", "2")
	if err != nil || op.Version != "2" {
		t.Fatalf("exact version lookup failed: op=%+v err=%v", op, err)
	}
}

func TestRegistryRejectsNilHandler(t *testing.T) {
	r := core.NewRegistry()
	if err := r.Register(&core.Operation{Name: "a"}, nil); err == nil {
		t.Fatal("nil handler")
	}
}

func TestDecisionDefaultDeny(t *testing.T) {
	var d core.Decision
	if d.Allowed() {
		t.Fatal("zero decision must not allow")
	}
}
