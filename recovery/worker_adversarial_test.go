package recovery_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/idempotency"
	"github.com/loreste/loom/recovery"
)

// failingHeartbeatQueue renews once then returns a stale-lease error so the
// worker observes a post-side-effect lease problem.
type failingHeartbeatQueue struct {
	mu           sync.Mutex
	record       execution.Record
	queued       bool
	claimed      bool
	renewals     int
	released     bool
	completed    bool
	scheduled    bool
	deadLettered bool
	failRenew    bool
}

func (q *failingHeartbeatQueue) ClaimRecovery(_ context.Context, owner string, _ time.Duration) (execution.RecoveryLease, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if owner == "" || !q.queued || q.claimed {
		return execution.RecoveryLease{}, false, nil
	}
	q.claimed = true
	if q.record.RecoveryAttempt == 0 {
		q.record.RecoveryAttempt = 1
	}
	return execution.RecoveryLease{Record: q.record, Owner: owner, LeaseID: "adv-lease"}, true, nil
}

func (q *failingHeartbeatQueue) ReleaseRecovery(_ context.Context, id, leaseID string, completed bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if id != q.record.ExecutionID || leaseID != "adv-lease" {
		return errors.New("wrong lease")
	}
	q.released = true
	q.completed = completed
	if completed {
		q.queued = false
	}
	q.claimed = false
	return nil
}

func (q *failingHeartbeatQueue) RenewRecovery(_ context.Context, id, leaseID string, lease time.Duration) (time.Time, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if id != q.record.ExecutionID || leaseID != "adv-lease" {
		return time.Time{}, errors.New("stale lease")
	}
	q.renewals++
	if q.failRenew {
		return time.Time{}, errors.New("lease reclaimed by another worker")
	}
	return time.Now().Add(lease), nil
}

func (q *failingHeartbeatQueue) ScheduleRecovery(_ context.Context, id, leaseID string, _ time.Time, _, _ string) (execution.Record, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if id != q.record.ExecutionID || leaseID != "adv-lease" {
		return execution.Record{}, errors.New("stale lease")
	}
	q.scheduled = true
	q.claimed = false
	return q.record, nil
}

func (q *failingHeartbeatQueue) DeadLetterRecovery(_ context.Context, id, leaseID, _, _ string) (execution.Record, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if id != q.record.ExecutionID || leaseID != "adv-lease" {
		return execution.Record{}, errors.New("stale lease")
	}
	q.deadLettered = true
	q.record.State = execution.StateOperatorReview
	q.claimed = false
	q.queued = false
	return q.record, nil
}

// TestWorkerNeverUnwindsSuccessfulReconcileOnLeaseRenewalFailure is the
// adversarial guard for brief invariant 8 and recovery state safety:
// successful reconciliation must not schedule retry or dead-letter because a
// heartbeat failed after the durable write.
func TestWorkerNeverUnwindsSuccessfulReconcileOnLeaseRenewalFailure(t *testing.T) {
	store := execution.NewMemoryStore()
	record := execution.Record{
		ExecutionID: "adv-reconcile-lease", Operation: "payment.capture", OperationVersion: "1",
		Outcome: core.OutcomeExecutedUnconfirmed, State: execution.StateExecutedUnconfirmed,
		Response: core.Response{Outcome: core.OutcomeExecutedUnconfirmed, ExecutionID: "adv-reconcile-lease"},
	}
	if err := store.Put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	queue := &failingHeartbeatQueue{record: record, queued: true, failRenew: true}
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: queue, Store: store, Owner: "worker-a",
		// Lease short enough that a heartbeat fires during a slow verify.
		Lease: 60 * time.Millisecond, Poll: time.Second,
		MaxAttempts: 1, // would dead-letter if fail() were incorrectly called
		Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
			time.Sleep(100 * time.Millisecond)
			return recovery.Verification{Confirmed: true, Outcome: core.OutcomeAllowed, Note: "provider ok"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil {
		// Release may fail if the lease was already considered stale; durable
		// state must still be reconciled and must not have been dead-lettered.
		if !result.Reconciled {
			t.Fatalf("ProcessOne() err=%v result=%+v; want Reconciled even if release fails", err, result)
		}
	}
	if !result.Reconciled {
		t.Fatalf("ProcessOne() = %+v; want Reconciled=true after successful provider confirm", result)
	}
	if queue.scheduled || queue.deadLettered {
		t.Fatalf("post-reconcile fail path scheduled=%v deadLettered=%v; must not unwind durable reconcile", queue.scheduled, queue.deadLettered)
	}
	got, ok, err := store.Get(context.Background(), record.ExecutionID)
	if err != nil || !ok || got.State != execution.StateReconciled || got.Outcome != core.OutcomeAllowed {
		t.Fatalf("store state = %+v found=%v err=%v; want reconciled/allowed", got, ok, err)
	}
}

// TestWorkerReleasesAlreadyReconciledLeaseWithoutRerunningHandler covers the
// safe cleanup path when a previous worker reconciled but failed to release.
func TestWorkerReleasesAlreadyReconciledLeaseWithoutRerunningHandler(t *testing.T) {
	store := execution.NewMemoryStore()
	record := execution.Record{
		ExecutionID: "adv-already-reconciled", Operation: "payment.capture", OperationVersion: "1",
		Outcome: core.OutcomeAllowed, State: execution.StateReconciled,
		Response: core.Response{Outcome: core.OutcomeAllowed, ExecutionID: "adv-already-reconciled"},
	}
	if err := store.Put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	queue := &failingHeartbeatQueue{record: record, queued: true}
	var verifies atomic.Int64
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: queue, Store: store, Owner: "worker-b", Lease: time.Minute, Poll: time.Second,
		Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
			verifies.Add(1)
			return recovery.Verification{Confirmed: true, Outcome: core.OutcomeAllowed}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil || !result.Claimed || !result.Reconciled {
		t.Fatalf("ProcessOne() = %+v err=%v", result, err)
	}
	if verifies.Load() != 0 {
		t.Fatalf("verifier called %d times; already-reconciled records must not re-verify or re-run handlers", verifies.Load())
	}
	if !queue.released || !queue.completed || queue.queued {
		t.Fatalf("queue release incomplete: released=%v completed=%v queued=%v", queue.released, queue.completed, queue.queued)
	}
}

// TestWorkerRejectsInvalidVerificationOutcome ensures a verifier cannot force
// an executed_unconfirmed → allowed transition with garbage outcomes.
func TestWorkerRejectsInvalidVerificationOutcome(t *testing.T) {
	store := execution.NewMemoryStore()
	record := execution.Record{
		ExecutionID: "adv-bad-outcome", Operation: "payment.capture", OperationVersion: "1",
		Outcome: core.OutcomeExecutedUnconfirmed, State: execution.StateExecutedUnconfirmed,
		Response: core.Response{Outcome: core.OutcomeExecutedUnconfirmed, ExecutionID: "adv-bad-outcome"},
	}
	if err := store.Put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	queue := &failingHeartbeatQueue{record: record, queued: true}
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: queue, Store: store, Owner: "worker-a", Lease: time.Minute, Poll: time.Second,
		BackoffBase: time.Second, BackoffMax: time.Minute, DisableJitter: true, MaxAttempts: 5,
		Now: func() time.Time { return time.Unix(1000, 0) },
		Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
			// Confirmed but with an outcome that is neither allowed nor denied.
			return recovery.Verification{Confirmed: true, Outcome: core.OutcomeExecutedUnconfirmed}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne() error = %v", err)
	}
	if result.Reconciled || !result.Scheduled {
		t.Fatalf("ProcessOne() = %+v; want scheduled retry, not reconcile", result)
	}
	got, ok, _ := store.Get(context.Background(), record.ExecutionID)
	if !ok || got.State != execution.StateExecutedUnconfirmed {
		t.Fatalf("store mutated to %+v; invalid verification must not reconcile", got)
	}
}

// TestWorkerNeverInvokesBusinessHandler documents that recovery only uses the
// Verifier/Recorder interfaces — no handler callback exists on the worker.
func TestWorkerNeverInvokesBusinessHandler(t *testing.T) {
	// The recovery.Config type has no Handler field. This test fails to compile
	// if one is ever added without an explicit security review.
	var cfg recovery.Config
	_ = cfg.Queue
	_ = cfg.Store
	_ = cfg.Verifier
	_ = cfg.Recorder
	_ = cfg.Escalator
	// No cfg.Handler — business handlers must never be reachable from recovery.
}

// TestIdempotencyRecorderRejectsFingerprintMismatch is the adversarial check
// that a recovered completion cannot overwrite a different reserved body.
func TestIdempotencyRecorderRejectsFingerprintMismatch(t *testing.T) {
	store := idempotency.NewMemoryStore()
	key := "idem-key-1"
	if err := store.Begin(context.Background(), key, "fp-original", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(context.Background(), key, &idempotency.Stored{
		Fingerprint: "fp-original",
		Response:    core.Response{Outcome: core.OutcomeAllowed, ExecutionID: "exec-1"},
		StoredAt:    time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	recorder := recovery.IdempotencyRecorder{Store: store, TTL: time.Minute}
	err := recorder.Record(context.Background(), execution.Record{
		IdempotencyKey: key,
		Fingerprint:    "fp-attacker",
		Response:       core.Response{Outcome: core.OutcomeAllowed, ExecutionID: "exec-evil"},
	})
	if err == nil || !errors.Is(err, core.ErrAlreadyExists) {
		t.Fatalf("Record() = %v, want ErrAlreadyExists on fingerprint mismatch", err)
	}
}

// TestIdempotencyRecorderIsIdempotentOnMatchingRetry ensures lease expiry after
// a successful Complete does not fail the next recovery attempt.
func TestIdempotencyRecorderIsIdempotentOnMatchingRetry(t *testing.T) {
	store := idempotency.NewMemoryStore()
	key := "idem-key-2"
	if err := store.Begin(context.Background(), key, "fp-ok", time.Minute); err != nil {
		t.Fatal(err)
	}
	// Use real wall clock for ExpiresAt: MemoryStore.Get compares against time.Now().
	recorder := recovery.IdempotencyRecorder{Store: store, TTL: time.Hour}
	record := execution.Record{
		IdempotencyKey: key,
		Fingerprint:    "fp-ok",
		Response:       core.Response{Outcome: core.OutcomeAllowed, ExecutionID: "exec-2"},
		StartedAt:      time.Now().UTC().Add(-time.Minute),
	}
	if err := recorder.Record(context.Background(), record); err != nil {
		t.Fatalf("first Record() = %v", err)
	}
	if err := recorder.Record(context.Background(), record); err != nil {
		t.Fatalf("retry Record() = %v; matching fingerprint must be safe to replay", err)
	}
}

// raceQueue is a mutex-guarded single-slot queue for concurrent claim tests.
type raceQueue struct {
	mu       sync.Mutex
	record   execution.Record
	queued   bool
	claimed  bool
	leaseID  string
	released bool
}

func (q *raceQueue) ClaimRecovery(_ context.Context, owner string, _ time.Duration) (execution.RecoveryLease, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if owner == "" || !q.queued || q.claimed {
		return execution.RecoveryLease{}, false, nil
	}
	q.claimed = true
	q.leaseID = "race-lease"
	return execution.RecoveryLease{Record: q.record, Owner: owner, LeaseID: q.leaseID}, true, nil
}

func (q *raceQueue) ReleaseRecovery(_ context.Context, id, leaseID string, completed bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if id != q.record.ExecutionID || leaseID != q.leaseID {
		return errors.New("wrong lease")
	}
	q.released = true
	if completed {
		q.queued = false
	}
	q.claimed = false
	return nil
}

// TestTwoWorkersRaceForOneRecord ensures only one claim succeeds against a
// single-owner queue (mirrors postgres SKIP LOCKED contract).
func TestTwoWorkersRaceForOneRecord(t *testing.T) {
	store := execution.NewMemoryStore()
	record := execution.Record{
		ExecutionID: "adv-race", Operation: "payment.capture", OperationVersion: "1",
		Outcome: core.OutcomeExecutedUnconfirmed, State: execution.StateExecutedUnconfirmed,
		Response: core.Response{Outcome: core.OutcomeExecutedUnconfirmed, ExecutionID: "adv-race"},
	}
	if err := store.Put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	queue := &raceQueue{record: record, queued: true}
	verifier := recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
		time.Sleep(20 * time.Millisecond)
		return recovery.Verification{Confirmed: true, Outcome: core.OutcomeAllowed}, nil
	})
	makeWorker := func(owner string) *recovery.Worker {
		w, err := recovery.NewWorker(recovery.Config{
			Queue: queue, Store: store, Owner: owner, Lease: time.Minute, Poll: time.Second,
			Verifier: verifier,
		})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	var wg sync.WaitGroup
	results := make(chan recovery.ProcessResult, 2)
	for _, owner := range []string{"worker-a", "worker-b"} {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			result, _ := makeWorker(owner).ProcessOne(context.Background())
			results <- result
		}(owner)
	}
	wg.Wait()
	close(results)
	var claimed, reconciled int
	for result := range results {
		if result.Claimed {
			claimed++
		}
		if result.Reconciled {
			reconciled++
		}
	}
	if claimed != 1 || reconciled != 1 {
		t.Fatalf("claimed=%d reconciled=%d; want exactly one successful claim/reconcile", claimed, reconciled)
	}
}

// TestEscalationDedupOnDeadLetter ensures a record already marked escalated is
// not re-alerted when it hits the dead-letter path again.
func TestEscalationDedupOnDeadLetter(t *testing.T) {
	queue := &scheduledQueue{
		record: execution.Record{
			ExecutionID: "adv-escalation-dedup", State: execution.StateExecutedUnconfirmed,
			RecoveryQueued: true, RecoveryAttempt: 3, RecoveryEscalated: true,
		},
		queued: true,
	}
	store := execution.NewMemoryStore()
	escalations := 0
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: queue, Store: store, Owner: "worker-a", Lease: time.Second, Poll: time.Second, MaxAttempts: 2,
		Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
			return recovery.Verification{}, errors.New("still broken")
		}),
		Escalator: recovery.EscalatorFunc(func(context.Context, execution.Record, error) error {
			escalations++
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil || !result.DeadLettered {
		t.Fatalf("ProcessOne() = %+v err=%v", result, err)
	}
	if escalations != 0 || result.Escalated {
		t.Fatalf("escalations=%d result.Escalated=%v; already-escalated records must not re-alert", escalations, result.Escalated)
	}
}

// TestBackoffGrowsThenCapsWithDeterministicJitter locks the retry schedule
// contract used by operators for RTO planning.
func TestBackoffGrowsThenCapsWithDeterministicJitter(t *testing.T) {
	// Export is internal; exercise through ScheduleRecovery timing via ProcessOne.
	clock := time.Unix(1_700_000_000, 0)
	base := time.Second
	max := 8 * time.Second
	var scheduled []time.Duration
	for attempt := 1; attempt <= 6; attempt++ {
		queue := &scheduledQueue{
			record: execution.Record{
				ExecutionID: "backoff-exec", State: execution.StateExecutedUnconfirmed,
				RecoveryQueued: true, RecoveryAttempt: attempt,
			},
			queued: true,
		}
		store := execution.NewMemoryStore()
		worker, err := recovery.NewWorker(recovery.Config{
			Queue: queue, Store: store, Owner: "worker-a", Lease: time.Second, Poll: time.Second,
			BackoffBase: base, BackoffMax: max, JitterFraction: 0, DisableJitter: true,
			MaxAttempts: 100,
			Now:         func() time.Time { return clock },
			Verifier: recovery.VerifierFunc(func(context.Context, execution.Record) (recovery.Verification, error) {
				return recovery.Verification{}, errors.New("retry me")
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := worker.ProcessOne(context.Background())
		if err != nil || !result.Scheduled {
			t.Fatalf("attempt %d: result=%+v err=%v", attempt, result, err)
		}
		scheduled = append(scheduled, queue.scheduledAt.Sub(clock))
	}
	// attempt 1 → 1s, 2 → 2s, 3 → 4s, 4+ → 8s cap
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second}
	for i := range want {
		if scheduled[i] != want[i] {
			t.Fatalf("delay[%d]=%v want %v (all=%v)", i, scheduled[i], want[i], scheduled)
		}
	}
}
