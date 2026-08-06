// Package recovery provides the official asynchronous worker for uncertain
// execution records. It verifies an external effect and reconciles status; it
// never invokes the original business handler.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/idempotency"
)

var ErrUnconfirmed = errors.New("recovery: external effect remains unconfirmed")

// Verification is the result returned by an external provider or operator
// lookup. A false Confirmed result stays queued for a later retry.
type Verification struct {
	Confirmed bool
	Outcome   core.Outcome
	Note      string
}

type Verifier interface {
	Verify(context.Context, execution.Record) (Verification, error)
}

type VerifierFunc func(context.Context, execution.Record) (Verification, error)

func (f VerifierFunc) Verify(ctx context.Context, record execution.Record) (Verification, error) {
	return f(ctx, record)
}

// Recorder retries durable completion such as an idempotency-store write.
// Implementations must be idempotent because a lease can expire after the
// remote system accepted the write.
type Recorder interface {
	Record(context.Context, execution.Record) error
}

type RecorderFunc func(context.Context, execution.Record) error

func (f RecorderFunc) Record(ctx context.Context, record execution.Record) error {
	return f(ctx, record)
}

// Escalator receives unresolved records and processing failures. It should
// create an operator/compliance alert without clearing the recovery queue.
type Escalator interface {
	Escalate(context.Context, execution.Record, error) error
}

type EscalatorFunc func(context.Context, execution.Record, error) error

func (f EscalatorFunc) Escalate(ctx context.Context, record execution.Record, err error) error {
	return f(ctx, record, err)
}

type Config struct {
	Queue     execution.RecoveryQueue
	Store     execution.Store
	Verifier  Verifier
	Recorder  Recorder
	Escalator Escalator
	Owner     string
	Lease     time.Duration
	Poll      time.Duration
	Logger    *log.Logger
}

type Worker struct {
	queue     execution.RecoveryQueue
	store     execution.Store
	verifier  Verifier
	recorder  Recorder
	escalator Escalator
	owner     string
	lease     time.Duration
	poll      time.Duration
	logger    *log.Logger
}

type ProcessResult struct {
	Claimed    bool
	Reconciled bool
	Escalated  bool
}

func NewWorker(config Config) (*Worker, error) {
	if config.Queue == nil || config.Store == nil || config.Verifier == nil {
		return nil, fmt.Errorf("recovery: queue, store, and verifier are required")
	}
	if config.Owner == "" || config.Lease <= 0 || config.Poll <= 0 {
		return nil, fmt.Errorf("recovery: owner, lease, and poll must be configured")
	}
	logger := config.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &Worker{
		queue: config.Queue, store: config.Store, verifier: config.Verifier,
		recorder: config.Recorder, escalator: config.Escalator,
		owner: config.Owner, lease: config.Lease, poll: config.Poll, logger: logger,
	}, nil
}

// Run polls until ctx is cancelled. Recoverable item failures are escalated
// and left queued; infrastructure errors are logged and retried next poll.
func (w *Worker) Run(ctx context.Context) error {
	if w == nil {
		return fmt.Errorf("recovery: nil worker")
	}
	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	for {
		if _, err := w.ProcessOne(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Printf("loom recovery worker: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// ProcessOne claims and processes at most one recovery record.
func (w *Worker) ProcessOne(ctx context.Context) (ProcessResult, error) {
	lease, ok, err := w.queue.ClaimRecovery(ctx, w.owner, w.lease)
	if err != nil || !ok {
		return ProcessResult{}, err
	}
	result := ProcessResult{Claimed: true}

	if lease.Record.State == execution.StateReconciled {
		if err := w.queue.ReleaseRecovery(ctx, lease.Record.ExecutionID, lease.LeaseID, true); err != nil {
			return result, err
		}
		return ProcessResult{Claimed: true, Reconciled: true}, nil
	}
	verification, err := w.verifier.Verify(ctx, lease.Record)
	if err != nil {
		return w.fail(ctx, lease, result, err)
	}
	if !verification.Confirmed {
		return w.fail(ctx, lease, result, fmt.Errorf("%w: %s", ErrUnconfirmed, verification.Note))
	}
	if verification.Outcome != core.OutcomeAllowed && verification.Outcome != core.OutcomeDenied {
		return w.fail(ctx, lease, result, fmt.Errorf("recovery: verifier returned invalid outcome %q", verification.Outcome))
	}
	if w.recorder != nil {
		if err := w.recorder.Record(ctx, lease.Record); err != nil {
			return w.fail(ctx, lease, result, fmt.Errorf("recovery: durable recording: %w", err))
		}
	}
	if _, err := w.store.Reconcile(ctx, lease.Record.ExecutionID, verification.Outcome, verification.Note); err != nil {
		return w.fail(ctx, lease, result, fmt.Errorf("recovery: reconcile: %w", err))
	}
	if err := w.queue.ReleaseRecovery(ctx, lease.Record.ExecutionID, lease.LeaseID, true); err != nil {
		return result, err
	}
	result.Reconciled = true
	return result, nil
}

func (w *Worker) fail(ctx context.Context, lease execution.RecoveryLease, result ProcessResult, cause error) (ProcessResult, error) {
	var escalationErr error
	if w.escalator != nil {
		escalationErr = w.escalator.Escalate(ctx, lease.Record, cause)
		result.Escalated = escalationErr == nil
	} else {
		w.logger.Printf("loom recovery worker: execution %s remains uncertain: %v", lease.Record.ExecutionID, cause)
	}
	if err := w.queue.ReleaseRecovery(ctx, lease.Record.ExecutionID, lease.LeaseID, false); err != nil {
		if escalationErr != nil {
			return result, fmt.Errorf("%v; recovery escalation: %v; release lease: %w", cause, escalationErr, err)
		}
		return result, err
	}
	if escalationErr != nil {
		return result, fmt.Errorf("%v; recovery escalation: %w", cause, escalationErr)
	}
	if w.escalator != nil {
		return result, nil
	}
	return result, cause
}

// IdempotencyRecorder completes a durable idempotency reservation from the
// response stored in an execution record. It is safe to retry after a lease
// expiry because the backend decides whether the completion is already done.
type IdempotencyRecorder struct {
	Store idempotency.Store
	TTL   time.Duration
	Clock func() time.Time
}

func (r IdempotencyRecorder) Record(ctx context.Context, record execution.Record) error {
	if r.Store == nil {
		return fmt.Errorf("recovery: idempotency store is not configured")
	}
	if record.IdempotencyKey == "" || record.Fingerprint == "" {
		return nil
	}
	if r.TTL <= 0 {
		return fmt.Errorf("recovery: idempotency TTL must be configured")
	}
	if existing, ok, err := r.Store.Get(ctx, record.IdempotencyKey); err != nil {
		return err
	} else if ok {
		if existing == nil {
			return fmt.Errorf("recovery: idempotency store returned an empty record")
		}
		if existing.Fingerprint != record.Fingerprint {
			return fmt.Errorf("%w: recovered idempotency fingerprint mismatch", core.ErrAlreadyExists)
		}
		return nil
	}
	now := time.Now
	if r.Clock != nil {
		now = r.Clock
	}
	created := record.StartedAt
	if created.IsZero() {
		created = now().UTC()
	}
	return r.Store.Complete(ctx, record.IdempotencyKey, &idempotency.Stored{
		Fingerprint: record.Fingerprint,
		Response:    record.Response,
		StoredAt:    created,
		ExpiresAt:   now().UTC().Add(r.TTL),
	})
}
