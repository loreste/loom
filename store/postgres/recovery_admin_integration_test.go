package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/store/postgres"
)

func TestPostgresRecoveryAdminStateTransitions(t *testing.T) {
	ctx := context.Background()
	b, err := postgres.NewBundle(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	id := "recovery-admin-" + time.Now().UTC().Format("20060102150405.000000000")
	if err := b.ExecutionStatus.Put(ctx, execution.Record{
		ExecutionID: id, Operation: "payment.capture", OperationVersion: "1", Boundary: "tenant-a",
		Outcome: core.OutcomeExecutedUnconfirmed, State: execution.StateExecutedUnconfirmed,
		Response: core.Response{ExecutionID: id, Outcome: core.OutcomeExecutedUnconfirmed},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ExecutionStatus.MarkRecoveryQueued(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ExecutionStatus.DeadLetterRecoveryAdmin(ctx, id, "operator review"); err != nil {
		t.Fatal(err)
	}
	review, err := b.ExecutionStatus.ListRecovery(ctx, execution.StateOperatorReview, 10)
	if err != nil || len(review) != 1 || review[0].ExecutionID != id {
		t.Fatalf("operator review list = %+v err=%v", review, err)
	}
	requeued, err := b.ExecutionStatus.RequeueRecovery(ctx, id, "approved requeue")
	if err != nil {
		t.Fatal(err)
	}
	if requeued.State != execution.StateExecutedUnconfirmed || !requeued.RecoveryQueued {
		t.Fatalf("requeued record = %+v", requeued)
	}
}
