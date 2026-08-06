package recovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/recovery"
)

type fakeQueue struct {
	record   execution.Record
	queued   bool
	claimed  bool
	released bool
}

func (q *fakeQueue) ClaimRecovery(_ context.Context, owner string, _ time.Duration) (execution.RecoveryLease, bool, error) {
	if owner == "" || !q.queued || q.claimed {
		return execution.RecoveryLease{}, false, nil
	}
	q.claimed = true
	return execution.RecoveryLease{Record: q.record, Owner: owner, LeaseID: "lease-1"}, true, nil
}

func (q *fakeQueue) ReleaseRecovery(_ context.Context, id, leaseID string, completed bool) error {
	if id != q.record.ExecutionID || leaseID != "lease-1" {
		return errors.New("wrong lease")
	}
	q.released = true
	if completed {
		q.queued = false
	}
	q.claimed = false
	return nil
}

func TestWorkerVerifiesReconcilesAndReleases(t *testing.T) {
	store := execution.NewMemoryStore()
	record := execution.Record{
		ExecutionID: "recovery-1", Operation: "payment.capture", OperationVersion: "1",
		Outcome: core.OutcomeExecutedUnconfirmed, State: execution.StateExecutedUnconfirmed,
		Response: core.Response{Outcome: core.OutcomeExecutedUnconfirmed, ExecutionID: "recovery-1"},
	}
	if err := store.Put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	queue := &fakeQueue{record: record, queued: true}
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: queue, Store: store, Owner: "worker-a", Lease: time.Minute, Poll: time.Second,
		Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
			return recovery.Verification{Confirmed: true, Outcome: core.OutcomeAllowed, Note: "provider confirmed"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil || !result.Claimed || !result.Reconciled || !queue.released {
		t.Fatalf("result=%+v err=%v queue=%+v", result, err, queue)
	}
	got, ok, err := store.Get(context.Background(), record.ExecutionID)
	if err != nil || !ok || got.State != execution.StateReconciled || got.Outcome != core.OutcomeAllowed {
		t.Fatalf("reconciled record=%+v found=%v err=%v", got, ok, err)
	}
}

func TestWorkerLeavesUnconfirmedRecordQueuedAndEscalates(t *testing.T) {
	store := execution.NewMemoryStore()
	record := execution.Record{ExecutionID: "recovery-2", Operation: "payment.capture", OperationVersion: "1", Outcome: core.OutcomeExecutedUnconfirmed, State: execution.StateExecutedUnconfirmed}
	if err := store.Put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	queue := &fakeQueue{record: record, queued: true}
	escalated := false
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: queue, Store: store, Owner: "worker-a", Lease: time.Minute, Poll: time.Second,
		Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
			return recovery.Verification{Note: "provider timeout"}, nil
		}),
		Escalator: recovery.EscalatorFunc(func(_ context.Context, got execution.Record, cause error) error {
			escalated = got.ExecutionID == record.ExecutionID && errors.Is(cause, recovery.ErrUnconfirmed)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil || !result.Escalated || !queue.released || queue.queued == false || !escalated {
		t.Fatalf("result=%+v err=%v queue=%+v escalated=%v", result, err, queue, escalated)
	}
}
