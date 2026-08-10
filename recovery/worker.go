// Package recovery provides the official asynchronous worker for uncertain
// execution records. It verifies an external effect and reconciles status; it
// never invokes the original business handler.
package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/idempotency"
)

const (
	defaultBackoffBase = 5 * time.Second
	defaultBackoffMax  = 5 * time.Minute
	defaultMaxAttempts = 5
	defaultJitter      = 0.2
)

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

// Escalator receives records that reached operator review. It should create an
// operator/compliance alert without clearing the recovery history.
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

	// Backoff controls durable retry scheduling when Queue also implements
	// execution.RecoveryScheduler. All values are bounded during construction.
	BackoffBase    time.Duration
	BackoffMax     time.Duration
	MaxAttempts    int
	JitterFraction float64
	DisableJitter  bool
	Now            func() time.Time
	Logger         *log.Logger

	// Observer receives bounded queue telemetry. Leave nil to disable it.
	Observer Observer
}

// Observer receives aggregate recovery telemetry. runtime.Metrics satisfies
// it. Queue gauges are reported separately from progress counters so a worker
// never resets a gauge it did not sample.
type Observer interface {
	ObserveRecoveryQueue(depth int64, oldestAge time.Duration)
	ObserveRecoveryProgress(attempts, renewals, deadLetters int64)
}

type Worker struct {
	queue       execution.RecoveryQueue
	store       execution.Store
	verifier    Verifier
	recorder    Recorder
	escalator   Escalator
	owner       string
	lease       time.Duration
	poll        time.Duration
	backoff     time.Duration
	backoffMax  time.Duration
	maxAttempts int
	jitter      float64
	now         func() time.Time
	logger      *log.Logger
	observer    Observer
}

type ProcessResult struct {
	Claimed      bool
	Reconciled   bool
	Scheduled    bool
	DeadLettered bool
	Escalated    bool
	Renewals     int
	Attempt      int
}

func NewWorker(config Config) (*Worker, error) {
	if config.Queue == nil || config.Store == nil || config.Verifier == nil {
		return nil, fmt.Errorf("recovery: queue, store, and verifier are required")
	}
	if config.Owner == "" || config.Lease <= 0 || config.Poll <= 0 {
		return nil, fmt.Errorf("recovery: owner, lease, and poll must be configured")
	}
	if config.BackoffBase <= 0 {
		config.BackoffBase = defaultBackoffBase
	}
	if config.BackoffMax <= 0 {
		config.BackoffMax = defaultBackoffMax
	}
	if config.BackoffMax < config.BackoffBase {
		return nil, fmt.Errorf("recovery: backoff max must be at least the base")
	}
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = defaultMaxAttempts
	}
	if config.JitterFraction == 0 && !config.DisableJitter {
		config.JitterFraction = defaultJitter
	}
	if config.JitterFraction < 0 || config.JitterFraction > 0.5 {
		return nil, fmt.Errorf("recovery: jitter fraction must be between 0 and 0.5")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	logger := config.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &Worker{
		queue:       config.Queue,
		store:       config.Store,
		verifier:    config.Verifier,
		recorder:    config.Recorder,
		escalator:   config.Escalator,
		owner:       config.Owner,
		lease:       config.Lease,
		poll:        config.Poll,
		backoff:     config.BackoffBase,
		backoffMax:  config.BackoffMax,
		maxAttempts: config.MaxAttempts,
		jitter:      config.JitterFraction,
		now:         config.Now,
		logger:      logger,
		observer:    config.Observer,
	}, nil
}

// Run polls until ctx is cancelled. Durable schedulers keep recoverable
// failures out of the hot loop until their next attempt is due.
func (w *Worker) Run(ctx context.Context) error {
	if w == nil {
		return fmt.Errorf("recovery: nil worker")
	}
	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	for {
		result, err := w.ProcessOne(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Printf("loom recovery worker: %v", err)
		}
		w.report(ctx, result)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// report publishes bounded telemetry for one poll iteration. Failures to
// sample the queue are ignored: telemetry must never stop recovery work.
//
// ponytail: samples depth once per poll interval; add a longer sample period
// if the indexed COUNT becomes measurable against a large queue.
func (w *Worker) report(ctx context.Context, result ProcessResult) {
	if w.observer == nil {
		return
	}
	var attempts, deadLetters int64
	if result.Claimed {
		attempts = 1
	}
	if result.DeadLettered {
		deadLetters = 1
	}
	w.observer.ObserveRecoveryProgress(attempts, int64(result.Renewals), deadLetters)
	counter, ok := w.queue.(execution.RecoveryCounter)
	if !ok {
		return
	}
	depth, oldest, err := counter.CountRecovery(ctx)
	if err != nil {
		return
	}
	var age time.Duration
	if !oldest.IsZero() {
		age = w.now().Sub(oldest)
	}
	w.observer.ObserveRecoveryQueue(depth, age)
}

// ProcessOne claims and processes at most one recovery record.
func (w *Worker) ProcessOne(ctx context.Context) (ProcessResult, error) {
	lease, ok, err := w.queue.ClaimRecovery(ctx, w.owner, w.lease)
	if err != nil || !ok {
		return ProcessResult{}, err
	}
	result := ProcessResult{Claimed: true, Attempt: lease.Record.RecoveryAttempt}
	if lease.Record.State == execution.StateReconciled {
		if err := w.queue.ReleaseRecovery(ctx, lease.Record.ExecutionID, lease.LeaseID, true); err != nil {
			return result, err
		}
		result.Reconciled = true
		return result, nil
	}

	workCtx, cancel := context.WithCancel(ctx)
	renewErr, renewDone := w.startHeartbeat(workCtx, cancel, lease, &result)
	verification, verifyErr := w.verifier.Verify(workCtx, lease.Record)
	if verifyErr != nil {
		cancel()
		<-renewDone
		return w.fail(ctx, lease, result, "verification_failed", "external verification failed", verifyErr)
	}
	if !verification.Confirmed {
		cancel()
		<-renewDone
		return w.fail(ctx, lease, result, "unconfirmed", "external effect remains unconfirmed", ErrUnconfirmed)
	}
	if verification.Outcome != core.OutcomeAllowed && verification.Outcome != core.OutcomeDenied {
		cancel()
		<-renewDone
		return w.fail(ctx, lease, result, "invalid_verification", "verification returned an invalid outcome", fmt.Errorf("recovery: invalid verification outcome"))
	}
	if w.recorder != nil {
		if err := w.recorder.Record(workCtx, lease.Record); err != nil {
			cancel()
			<-renewDone
			return w.fail(ctx, lease, result, "recording_failed", "durable recording failed", err)
		}
	}
	if _, err := w.store.Reconcile(ctx, lease.Record.ExecutionID, verification.Outcome, verification.Note); err != nil {
		cancel()
		<-renewDone
		return w.fail(ctx, lease, result, "reconciliation_failed", "execution reconciliation failed", err)
	}
	// Durable state is reconciled. Lease renewal or release failures must not
	// schedule retries or dead-letter the record: the next worker reclaims an
	// expired lease, observes StateReconciled, and releases completed.
	result.Reconciled = true
	cancel()
	<-renewDone
	// Drain heartbeat outcome; a late renewal error is irrelevant after a
	// successful reconciliation and must never reverse durable progress.
	_ = <-renewErr
	if err := w.queue.ReleaseRecovery(ctx, lease.Record.ExecutionID, lease.LeaseID, true); err != nil {
		return result, err
	}
	return result, nil
}

func (w *Worker) startHeartbeat(ctx context.Context, cancel context.CancelFunc, lease execution.RecoveryLease, result *ProcessResult) (<-chan error, <-chan struct{}) {
	errCh := make(chan error, 1)
	done := make(chan struct{})
	heartbeat, ok := w.queue.(execution.RecoveryHeartbeat)
	if !ok {
		close(errCh)
		close(done)
		return errCh, done
	}
	go func() {
		defer close(done)
		defer close(errCh)
		interval := w.lease / 3
		if interval <= 0 {
			interval = time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := heartbeat.RenewRecovery(ctx, lease.Record.ExecutionID, lease.LeaseID, w.lease); err != nil {
					errCh <- err
					cancel()
					return
				}
				result.Renewals++
			}
		}
	}()
	return errCh, done
}

func (w *Worker) fail(ctx context.Context, lease execution.RecoveryLease, result ProcessResult, category, summary string, cause error) (ProcessResult, error) {
	if scheduler, ok := w.queue.(execution.RecoveryScheduler); ok {
		attempt := lease.Record.RecoveryAttempt
		if attempt <= 0 {
			attempt = 1
		}
		if attempt >= w.maxAttempts {
			var escalationErr error
			if !lease.Record.RecoveryEscalated && w.escalator != nil {
				escalationErr = w.escalator.Escalate(ctx, lease.Record, cause)
				result.Escalated = escalationErr == nil
			}
			if _, err := scheduler.DeadLetterRecovery(ctx, lease.Record.ExecutionID, lease.LeaseID, category, summary); err != nil {
				return result, fmt.Errorf("%s: dead-letter: %w", summary, err)
			}
			result.DeadLettered = true
			if escalationErr != nil {
				return result, fmt.Errorf("%s: escalation: %w", summary, escalationErr)
			}
			return result, nil
		}
		next := w.now().UTC().Add(retryDelay(w.backoff, w.backoffMax, attempt, lease.Record.ExecutionID, w.jitter))
		if _, err := scheduler.ScheduleRecovery(ctx, lease.Record.ExecutionID, lease.LeaseID, next, category, summary); err != nil {
			return result, fmt.Errorf("%s: schedule: %w", summary, err)
		}
		result.Scheduled = true
		return result, nil
	}

	var escalationErr error
	// Deduplicate against RecoveryEscalated so repeated claim/release cycles
	// without a durable scheduler cannot page operators on every poll.
	if w.escalator != nil && !lease.Record.RecoveryEscalated {
		escalationErr = w.escalator.Escalate(ctx, lease.Record, cause)
		result.Escalated = escalationErr == nil
	} else if w.escalator == nil {
		w.logger.Printf("loom recovery worker: execution %s remains uncertain: %s", lease.Record.ExecutionID, summary)
	}
	if err := w.queue.ReleaseRecovery(ctx, lease.Record.ExecutionID, lease.LeaseID, false); err != nil {
		if escalationErr != nil {
			return result, fmt.Errorf("%s; recovery escalation: %v; release lease: %w", summary, escalationErr, err)
		}
		return result, err
	}
	if escalationErr != nil {
		return result, fmt.Errorf("%s; recovery escalation: %w", summary, escalationErr)
	}
	if w.escalator != nil {
		return result, nil
	}
	return result, cause
}

func retryDelay(base, max time.Duration, attempt int, executionID string, jitter float64) time.Duration {
	delay := base
	for i := 1; i < attempt && delay < max; i++ {
		if delay > max/2 {
			delay = max
			break
		}
		delay *= 2
	}
	if delay > max {
		delay = max
	}
	if jitter == 0 {
		return delay
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", executionID, attempt)))
	unit := float64(binary.BigEndian.Uint64(digest[:8])) / float64(^uint64(0))
	factor := 1 + ((unit*2)-1)*jitter
	result := time.Duration(float64(delay) * factor)
	if result < time.Millisecond {
		return time.Millisecond
	}
	if result > max {
		return max
	}
	return result
}

// IdempotencyRecorder completes a durable idempotency reservation from the
// response stored in an execution record. It is safe to retry after a lease
// expiry because the backend decides whether completion is already done.
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

var ErrUnconfirmed = errors.New("recovery: external effect remains unconfirmed")
