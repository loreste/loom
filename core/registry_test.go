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
