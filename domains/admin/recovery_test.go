package admin

import (
	"context"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
)

type fakeRecoveryAdmin struct {
	record execution.Record
	called string
}

func (f *fakeRecoveryAdmin) ListRecovery(context.Context, execution.State, int) ([]execution.Record, error) {
	return []execution.Record{f.record}, nil
}

func (f *fakeRecoveryAdmin) RequeueRecovery(context.Context, string, string) (execution.Record, error) {
	f.called = "requeue"
	return f.record, nil
}

func (f *fakeRecoveryAdmin) DeadLetterRecoveryAdmin(context.Context, string, string) (execution.Record, error) {
	f.called = "dead-letter"
	return f.record, nil
}

func TestRecoveryAdminOperationsRequireExplicitRegistrationAndReturnSafeSummary(t *testing.T) {
	store := &fakeRecoveryAdmin{record: execution.Record{
		ExecutionID: "exec-1", Operation: "payment.capture", OperationVersion: "1", Boundary: "tenant-a",
		State: execution.StateOperatorReview, Outcome: core.OutcomeExecutedUnconfirmed,
		IdempotencyKey: "must-not-leak", Fingerprint: "must-not-leak",
	}}
	registry := core.NewRegistry()
	if err := RegisterRecovery(registry, RecoveryDeps{Store: store}); err != nil {
		t.Fatal(err)
	}
	listHandler, err := registry.HandlerVersion(OpRecoveryList, "1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := listHandler(&core.ExecutionContext{Ctx: context.Background(), Input: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Output["records"] == nil {
		t.Fatalf("list result = %+v", result)
	}
	if _, leaked := result.Output["idempotency_key"]; leaked {
		t.Fatal("recovery summary leaked idempotency key")
	}
	requeueHandler, err := registry.HandlerVersion(OpRecoveryRequeue, "1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := requeueHandler(&core.ExecutionContext{Ctx: context.Background(), Input: map[string]any{"execution_id": "exec-1"}}); err != nil {
		t.Fatal(err)
	}
	if store.called != "requeue" {
		t.Fatalf("store called = %q", store.called)
	}
	if op, err := registry.GetVersion(OpRecoveryRequeue, "1"); err != nil || !op.Approval.Required {
		t.Fatalf("requeue operation approval = %+v err=%v", op, err)
	}
}
