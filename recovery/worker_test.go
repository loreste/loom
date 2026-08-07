package recovery_test

import (
	"context"
	"errors"
	"sync"
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

type scheduledQueue struct {
	mu          sync.Mutex
	record      execution.Record
	claimed     bool
	queued      bool
	renewals    int
	scheduledAt time.Time
	deadLetter  bool
}

func (q *scheduledQueue) ClaimRecovery(_ context.Context, owner string, _ time.Duration) (execution.RecoveryLease, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if owner == "" || !q.queued || q.claimed {
		return execution.RecoveryLease{}, false, nil
	}
	q.claimed = true
	if q.record.RecoveryAttempt == 0 {
		q.record.RecoveryAttempt = 1
	}
	return execution.RecoveryLease{Record: q.record, Owner: owner, LeaseID: "scheduled-lease"}, true, nil
}

func (q *scheduledQueue) ReleaseRecovery(_ context.Context, id, leaseID string, completed bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if id != q.record.ExecutionID || leaseID != "scheduled-lease" {
		return errors.New("wrong lease")
	}
	q.queued = !completed
	q.claimed = false
	return nil
}

func (q *scheduledQueue) RenewRecovery(_ context.Context, id, leaseID string, lease time.Duration) (time.Time, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if id != q.record.ExecutionID || leaseID != "scheduled-lease" || !q.claimed {
		return time.Time{}, errors.New("stale lease")
	}
	q.renewals++
	return time.Now().Add(lease), nil
}

func (q *scheduledQueue) ScheduleRecovery(_ context.Context, id, leaseID string, next time.Time, category, summary string) (execution.Record, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if id != q.record.ExecutionID || leaseID != "scheduled-lease" || !q.claimed {
		return execution.Record{}, errors.New("stale lease")
	}
	q.record.NextAttemptAt = next
	q.record.LastFailureCategory = category
	q.record.LastFailureSummary = summary
	q.scheduledAt = next
	q.claimed = false
	return q.record, nil
}

func (q *scheduledQueue) DeadLetterRecovery(_ context.Context, id, leaseID, category, summary string) (execution.Record, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if id != q.record.ExecutionID || leaseID != "scheduled-lease" || !q.claimed {
		return execution.Record{}, errors.New("stale lease")
	}
	q.record.State = execution.StateOperatorReview
	q.record.RecoveryQueued = false
	q.record.LastFailureCategory = category
	q.record.LastFailureSummary = summary
	q.deadLetter = true
	q.claimed = false
	return q.record, nil
}

func TestWorkerSchedulesBoundedRetryWithDeterministicBackoff(t *testing.T) {
	queue := &scheduledQueue{
		record: execution.Record{ExecutionID: "scheduled-1", State: execution.StateExecutedUnconfirmed, RecoveryQueued: true},
		queued: true,
	}
	store := execution.NewMemoryStore()
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: queue, Store: store,
		Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
			return recovery.Verification{}, errors.New("provider timeout")
		}),
		Owner: "worker-a", Lease: time.Second, Poll: time.Second,
		BackoffBase: time.Second, BackoffMax: 10 * time.Second, JitterFraction: 0, DisableJitter: true,
		Now: func() time.Time { return time.Unix(100, 0) },
	})
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil || !result.Scheduled {
		t.Fatalf("ProcessOne() = %#v, %v", result, err)
	}
	if want := time.Unix(101, 0); !queue.scheduledAt.Equal(want) {
		t.Fatalf("scheduled time = %v, want %v", queue.scheduledAt, want)
	}
}

func TestWorkerDeadLettersAfterMaximumAttemptsAndEscalatesOnce(t *testing.T) {
	queue := &scheduledQueue{
		record: execution.Record{ExecutionID: "dead-letter-1", State: execution.StateExecutedUnconfirmed, RecoveryQueued: true, RecoveryAttempt: 2},
		queued: true,
	}
	store := execution.NewMemoryStore()
	escalations := 0
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: queue, Store: store,
		Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
			return recovery.Verification{}, errors.New("provider unavailable")
		}),
		Escalator: recovery.EscalatorFunc(func(context.Context, execution.Record, error) error {
			escalations++
			return nil
		}),
		Owner: "worker-a", Lease: time.Second, Poll: time.Second, MaxAttempts: 2,
	})
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil || !result.DeadLettered || !result.Escalated || !queue.deadLetter || escalations != 1 {
		t.Fatalf("ProcessOne() = %#v, err=%v escalations=%d dead=%v", result, err, escalations, queue.deadLetter)
	}
}

func TestWorkerRenewsLongVerificationLease(t *testing.T) {
	queue := &scheduledQueue{
		record: execution.Record{ExecutionID: "heartbeat-1", Operation: "test", OperationVersion: "1", State: execution.StateExecutedUnconfirmed, RecoveryQueued: true},
		queued: true,
	}
	store := execution.NewMemoryStore()
	if err := store.Put(context.Background(), queue.record); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: queue, Store: store,
		Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
			time.Sleep(80 * time.Millisecond)
			return recovery.Verification{Confirmed: true, Outcome: core.OutcomeAllowed}, nil
		}),
		Owner: "worker-a", Lease: 150 * time.Millisecond, Poll: time.Second,
	})
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil || !result.Reconciled || queue.renewals == 0 {
		t.Fatalf("ProcessOne() = %#v, err=%v renewals=%d", result, err, queue.renewals)
	}
}

// countingQueue reports queue depth so the worker can publish gauges.
type countingQueue struct {
	fakeQueue
	oldest time.Time
}

func (q *countingQueue) CountRecovery(context.Context) (int64, time.Time, error) {
	if !q.queued {
		return 0, time.Time{}, nil
	}
	return 4, q.oldest, nil
}

type recordingObserver struct {
	mu          sync.Mutex
	depth       int64
	oldestAge   time.Duration
	attempts    int64
	renewals    int64
	deadLetters int64
	sampled     chan struct{}
	sampledOnce sync.Once
}

func (o *recordingObserver) ObserveRecoveryQueue(depth int64, oldestAge time.Duration) {
	o.mu.Lock()
	o.depth, o.oldestAge = depth, oldestAge
	o.mu.Unlock()
	o.sampledOnce.Do(func() { close(o.sampled) })
}

func (o *recordingObserver) ObserveRecoveryProgress(attempts, renewals, deadLetters int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.attempts += attempts
	o.renewals += renewals
	o.deadLetters += deadLetters
}

func TestWorkerReportsQueueDepthAndProgress(t *testing.T) {
	store := execution.NewMemoryStore()
	record := execution.Record{
		ExecutionID: "recovery-metrics", Operation: "payment.capture", OperationVersion: "1",
		Outcome: core.OutcomeExecutedUnconfirmed, State: execution.StateExecutedUnconfirmed,
		Response: core.Response{Outcome: core.OutcomeExecutedUnconfirmed, ExecutionID: "recovery-metrics"},
	}
	if err := store.Put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	queue := &countingQueue{
		fakeQueue: fakeQueue{record: record, queued: true},
		oldest:    time.Now().Add(-90 * time.Second),
	}
	observer := &recordingObserver{sampled: make(chan struct{})}
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: queue, Store: store, Owner: "worker-a", Lease: time.Minute, Poll: time.Millisecond,
		Observer: observer,
		Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
			return recovery.Verification{Confirmed: true, Outcome: core.OutcomeAllowed}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = worker.Run(ctx) }()
	select {
	case <-observer.sampled:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("worker never reported a queue sample")
	}
	cancel()
	<-done

	observer.mu.Lock()
	defer observer.mu.Unlock()
	if observer.attempts < 1 {
		t.Fatalf("attempts = %d, want at least 1", observer.attempts)
	}
	if observer.depth != 4 && observer.depth != 0 {
		t.Fatalf("depth = %d, want the queue-reported 4 or 0 once drained", observer.depth)
	}
	if observer.depth == 4 && observer.oldestAge < 60*time.Second {
		t.Fatalf("oldestAge = %s, want the age of the oldest queued record", observer.oldestAge)
	}
}
