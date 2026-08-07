package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/policy"
)

// failingStore fails Put so the error path is measured as well as the latency.
type failingStore struct {
	execution.Store
	fail bool
}

func (s *failingStore) Put(ctx context.Context, record execution.Record) error {
	if s.fail {
		return errors.New("durable store unavailable")
	}
	return s.Store.Put(ctx, record)
}

func newObservedStack(t *testing.T, store execution.Store) (*TestStack, *Metrics, core.Request) {
	t.Helper()
	stack, err := NewTestStack()
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.Verifier.Register(identity.StaticPrincipal{
		ID: "user:alice", Type: "user", Boundary: "dev", Token: "tok-alice",
		Capabilities: []string{"profile.read"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := stack.Boundary.Grant("user:alice", "dev"); err != nil {
		t.Fatal(err)
	}
	if err := stack.Policy.AddRule(policy.Rule{
		Principal: "user:alice", Boundary: "dev", Operation: "profile.read",
		OperationVersion: "1", Priority: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := stack.Registry.Register(&core.Operation{
		Name: "profile.read", Version: "1", Permissions: []string{"profile.read"},
		Risk: core.RiskLow, Effects: []core.Effect{core.EffectRead},
	}, func(*core.ExecutionContext) (*core.Result, error) {
		return &core.Result{Output: map[string]any{"status": "ok"}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	metrics := NewMetrics()
	stack.Runtime.deps.Observer = metrics
	if store != nil {
		stack.Runtime.deps.ExecutionStatus = store
	}
	req := core.Request{
		Operation: "profile.read", OperationVersion: "1", Boundary: "dev",
		Credentials: core.Credentials{Scheme: "bearer", Token: "tok-alice"},
		Input:       map[string]any{"id": "profile-1"},
	}
	return stack, metrics, req
}

func TestExecuteReportsDurableStoreMetrics(t *testing.T) {
	stack, metrics, req := newObservedStack(t, nil)
	if resp := stack.Runtime.Execute(context.Background(), req); resp.Decision != core.DecisionAllow {
		t.Fatalf("Execute decision = %v, denial=%+v", resp.Decision, resp.Denial)
	}
	snapshot := metrics.Snapshot()
	if got := snapshot["durable_store_calls"]; got == int64(0) {
		t.Fatalf("durable_store_calls = %v, want a recorded write", got)
	}
	if got := snapshot["durable_store_errors"]; got != int64(0) {
		t.Fatalf("durable_store_errors = %v, want 0 on the success path", got)
	}
}

func TestExecuteReportsDurableStoreFailure(t *testing.T) {
	store := &failingStore{Store: execution.NewMemoryStore(), fail: true}
	stack, metrics, req := newObservedStack(t, store)
	if resp := stack.Runtime.Execute(context.Background(), req); resp.Decision != core.DecisionDeny {
		t.Fatalf("Execute decision = %v, want deny when the durable write fails", resp.Decision)
	}
	if got := metrics.Snapshot()["durable_store_errors"]; got != int64(1) {
		t.Fatalf("durable_store_errors = %v, want 1", got)
	}
}
