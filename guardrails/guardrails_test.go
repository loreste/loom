package guardrails_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/guardrails"
)

func TestSchemaRequired(t *testing.T) {
	op := &core.Operation{
		InputSchema: []byte(`{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}`),
	}
	req := &core.Request{Input: map[string]any{}}
	res := guardrails.SchemaGuard{}.Check(context.Background(), core.Identity{}, op, req)
	if res.OK {
		t.Fatal("expected schema fail")
	}
}

func TestRedactSecrets(t *testing.T) {
	m := guardrails.RedactSecrets(map[string]any{
		"token": "sk-abcdefghijklmnopqrstuvwxyz",
		"ok":    "hello",
	})
	if m["token"] != "[REDACTED]" {
		t.Fatalf("got %v", m["token"])
	}
	if m["ok"] != "hello" {
		t.Fatal("false positive redaction")
	}
}

func TestChainPanicIsDeny(t *testing.T) {
	c := guardrails.NewChain(panicGuard{})
	res := c.Check(context.Background(), core.Identity{}, &core.Operation{}, &core.Request{Input: map[string]any{}})
	if res.OK {
		t.Fatal("panic must fail closed")
	}
}

type panicGuard struct{}

func (panicGuard) Name() string { return "panic" }
func (panicGuard) Check(context.Context, core.Identity, *core.Operation, *core.Request) guardrails.Result {
	panic("boom")
}
