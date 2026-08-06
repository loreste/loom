package execution_test

import (
	"context"
	"errors"
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

func TestMemoryStorePutIsImmutableAndCompleteIsExplicit(t *testing.T) {
	store := execution.NewMemoryStore()
	record := execution.Record{
		ExecutionID:      "immutable-memory",
		Operation:        "profile.update",
		OperationVersion: "1",
		Outcome:          core.OutcomeDenied,
		State:            execution.StatePending,
		Response:         core.Response{Outcome: core.OutcomeDenied, ExecutionID: "immutable-memory"},
	}
	if err := store.Put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), record); !errors.Is(err, core.ErrAlreadyExists) {
		t.Fatalf("duplicate Put error = %v, want ErrAlreadyExists", err)
	}
	completed := record
	completed.Outcome = core.OutcomeAllowed
	completed.State = execution.StateAllowed
	completed.Response = core.Response{Outcome: core.OutcomeAllowed, Allowed: true, ExecutionID: record.ExecutionID}
	if err := store.Complete(context.Background(), completed); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(context.Background(), record.ExecutionID)
	if err != nil || !ok {
		t.Fatalf("Get after Complete: record=%+v found=%v err=%v", got, ok, err)
	}
	if got.State != execution.StateAllowed || got.Outcome != core.OutcomeAllowed {
		t.Fatalf("unexpected completed record: %+v", got)
	}
	if err := store.Complete(context.Background(), completed); !errors.Is(err, core.ErrAlreadyExists) {
		t.Fatalf("second Complete error = %v, want ErrAlreadyExists", err)
	}
}
