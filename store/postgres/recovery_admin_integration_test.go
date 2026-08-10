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
	clearRecoveryQueue(t, b.DB)
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

// CountRecovery drives the recovery depth and age gauges, so its SQL is
// exercised against a real database rather than a fake queue.
func TestPostgresCountRecovery(t *testing.T) {
	ctx := context.Background()
	b, err := postgres.NewBundle(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	clearRecoveryQueue(t, b.DB)

	before, _, err := b.ExecutionStatus.CountRecovery(ctx)
	if err != nil {
		t.Fatal(err)
	}

	id := "recovery-count-" + time.Now().UTC().Format("20060102150405.000000000")
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

	depth, oldest, err := b.ExecutionStatus.CountRecovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if depth != before+1 {
		t.Fatalf("depth = %d, want %d after queueing one record", depth, before+1)
	}
	if oldest.IsZero() {
		t.Fatal("oldest update time is zero while a record is queued")
	}
	if age := time.Since(oldest); age < 0 || age > time.Hour {
		t.Fatalf("oldest = %s produces an implausible age of %s", oldest, age)
	}

	// Leaving the queue must decrease the depth again.
	if _, err := b.ExecutionStatus.DeadLetterRecoveryAdmin(ctx, id, "operator review"); err != nil {
		t.Fatal(err)
	}
	after, _, err := b.ExecutionStatus.CountRecovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("depth = %d after dequeue, want %d", after, before)
	}
}

// TestPostgresDeadLetterAndScheduleRefuseReconciledState guards the invariant
// that a late worker failure after successful Reconcile must never rewrite
// durable state into operator_review or re-schedule retry.
func TestPostgresDeadLetterAndScheduleRefuseReconciledState(t *testing.T) {
	ctx := context.Background()
	b, err := postgres.NewBundle(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	clearRecoveryQueue(t, b.DB)

	id := "recovery-reconciled-guard-" + time.Now().UTC().Format("20060102150405.000000000")
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
	lease, ok, err := b.ExecutionStatus.ClaimRecovery(ctx, "worker-guard", time.Minute)
	if err != nil || !ok {
		t.Fatalf("ClaimRecovery: ok=%v err=%v", ok, err)
	}
	// Reconcile while the lease is still held — the dangerous race window.
	if _, err := b.ExecutionStatus.Reconcile(ctx, id, core.OutcomeAllowed, "provider confirmed"); err != nil {
		t.Fatal(err)
	}
	// Worker mistakenly tries to dead-letter or schedule after reconcile.
	if _, err := b.ExecutionStatus.DeadLetterRecovery(ctx, id, lease.LeaseID, "lease_renewal_failed", "stale"); err == nil {
		t.Fatal("DeadLetterRecovery must refuse a reconciled execution")
	}
	if _, err := b.ExecutionStatus.ScheduleRecovery(ctx, id, lease.LeaseID, time.Now().UTC().Add(time.Minute), "lease_renewal_failed", "stale"); err == nil {
		t.Fatal("ScheduleRecovery must refuse a reconciled execution")
	}
	// Release completed still works so the next worker can finish cleanup.
	if err := b.ExecutionStatus.ReleaseRecovery(ctx, id, lease.LeaseID, true); err != nil {
		t.Fatal(err)
	}
	got, found, err := b.ExecutionStatus.Get(ctx, id)
	if err != nil || !found {
		t.Fatalf("Get: found=%v err=%v", found, err)
	}
	if got.State != execution.StateReconciled || got.Outcome != core.OutcomeAllowed {
		t.Fatalf("durable state corrupted: %+v", got)
	}
	if got.RecoveryQueued {
		t.Fatal("completed release must clear recovery_queued")
	}
}
