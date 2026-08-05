package execution_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
)

func TestMemoryStoreReconcilesExecutedUnconfirmed(t *testing.T) {
	store := execution.NewMemoryStore()
	record := execution.Record{
		ExecutionID:      "exec-1",
		Operation:        "payment.capture",
		OperationVersion: "1",
		Outcome:          core.OutcomeExecutedUnconfirmed,
		State:            execution.StateExecutedUnconfirmed,
		Response:         core.Response{Outcome: core.OutcomeExecutedUnconfirmed, ExecutionID: "exec-1"},
	}
	if err := store.Put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	got, err := store.Reconcile(context.Background(), "exec-1", core.OutcomeAllowed, "processor confirmed")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != execution.StateReconciled || !got.Response.Allowed || got.Response.ReliabilityWarning != "" {
		t.Fatalf("unexpected reconciled record: %+v", got)
	}
}
