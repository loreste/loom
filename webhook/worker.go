package webhook

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"time"
)

const (
	defaultWorkerBackoffBase = time.Second
	defaultWorkerBackoffMax  = 5 * time.Minute
	defaultWorkerMaxAttempts = 8
	defaultWorkerJitter      = 0.2
)

// Deliverer performs the HTTP delivery for one outbox record.
type Deliverer interface {
	Deliver(context.Context, OutboxRecord) error
}

// HTTPDeliverer adapts Sink to the worker Deliverer interface.
type HTTPDeliverer struct {
	Sink *Sink
}

// Deliver posts the event through the hardened transport.
func (d HTTPDeliverer) Deliver(ctx context.Context, record OutboxRecord) error {
	if d.Sink == nil {
		return fmt.Errorf("webhook: deliverer sink is not configured")
	}
	return d.Sink.DeliverEvent(ctx, record.Event)
}

// WorkerConfig configures the durable outbox delivery worker.
type WorkerConfig struct {
	Outbox    Outbox
	Deliverer Deliverer
	Owner          string
	Lease          time.Duration
	Poll           time.Duration
	BackoffBase    time.Duration
	BackoffMax     time.Duration
	MaxAttempts    int
	JitterFraction float64
	DisableJitter  bool
	Now            func() time.Time
	Logger         *log.Logger
	Observer       WorkerObserver
}

// WorkerObserver receives bounded outbox telemetry.
type WorkerObserver interface {
	ObserveWebhookQueue(depth int64, oldestAge time.Duration)
	ObserveWebhookProgress(attempts, deliveries, failures, deadLetters int64)
}

// Worker drains the durable outbox. It never invokes business handlers.
type Worker struct {
	outbox      Outbox
	deliverer   Deliverer
	owner       string
	lease       time.Duration
	poll        time.Duration
	backoff     time.Duration
	backoffMax  time.Duration
	maxAttempts int
	jitter      float64
	now         func() time.Time
	logger      *log.Logger
	observer    WorkerObserver
}

// ProcessResult summarizes one poll iteration.
type ProcessResult struct {
	Claimed      bool
	Delivered    bool
	Scheduled    bool
	DeadLettered bool
	Attempt      int
	Renewals     int
}

// NewWorker constructs a delivery worker.
func NewWorker(cfg WorkerConfig) (*Worker, error) {
	if cfg.Outbox == nil || cfg.Deliverer == nil {
		return nil, fmt.Errorf("webhook: outbox and deliverer are required")
	}
	if cfg.Owner == "" || cfg.Lease <= 0 || cfg.Poll <= 0 {
		return nil, fmt.Errorf("webhook: owner, lease, and poll must be configured")
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = defaultWorkerBackoffBase
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = defaultWorkerBackoffMax
	}
	if cfg.BackoffMax < cfg.BackoffBase {
		return nil, fmt.Errorf("webhook: backoff max must be at least the base")
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultWorkerMaxAttempts
	}
	if cfg.JitterFraction == 0 && !cfg.DisableJitter {
		cfg.JitterFraction = defaultWorkerJitter
	}
	if cfg.JitterFraction < 0 || cfg.JitterFraction > 0.5 {
		return nil, fmt.Errorf("webhook: jitter fraction must be between 0 and 0.5")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &Worker{
		outbox:      cfg.Outbox,
		deliverer:   cfg.Deliverer,
		owner:       cfg.Owner,
		lease:       cfg.Lease,
		poll:        cfg.Poll,
		backoff:     cfg.BackoffBase,
		backoffMax:  cfg.BackoffMax,
		maxAttempts: cfg.MaxAttempts,
		jitter:      cfg.JitterFraction,
		now:         cfg.Now,
		logger:      logger,
		observer:    cfg.Observer,
	}, nil
}

// Run polls until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	if w == nil {
		return fmt.Errorf("webhook: nil worker")
	}
	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	for {
		result, err := w.ProcessOne(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Printf("loom webhook worker: %v", err)
		}
		w.report(ctx, result)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (w *Worker) report(ctx context.Context, result ProcessResult) {
	if w.observer == nil {
		return
	}
	var attempts, deliveries, failures, deadLetters int64
	if result.Claimed {
		attempts = 1
	}
	if result.Delivered {
		deliveries = 1
	}
	if result.Scheduled {
		failures = 1
	}
	if result.DeadLettered {
		deadLetters = 1
	}
	w.observer.ObserveWebhookProgress(attempts, deliveries, failures, deadLetters)
	depth, oldest, err := w.outbox.Count(ctx)
	if err != nil {
		return
	}
	var age time.Duration
	if !oldest.IsZero() {
		age = w.now().Sub(oldest)
	}
	w.observer.ObserveWebhookQueue(depth, age)
}

// ProcessOne claims and delivers at most one outbox record.
func (w *Worker) ProcessOne(ctx context.Context) (ProcessResult, error) {
	lease, ok, err := w.outbox.Claim(ctx, w.owner, w.lease)
	if err != nil || !ok {
		return ProcessResult{}, err
	}
	result := ProcessResult{Claimed: true, Attempt: lease.Record.Attempt}
	if lease.Record.State == StateDelivered {
		_ = w.outbox.MarkDelivered(ctx, lease.Record.ID, lease.LeaseID)
		result.Delivered = true
		return result, nil
	}

	workCtx, cancel := context.WithCancel(ctx)
	renewErr, renewDone := w.startHeartbeat(workCtx, cancel, lease, &result)
	deliverErr := w.deliverer.Deliver(workCtx, lease.Record)
	cancel()
	<-renewDone
	if deliverErr != nil {
		return w.fail(ctx, lease, result, "delivery_failed", "webhook delivery failed", deliverErr)
	}
	_ = <-renewErr
	if err := w.outbox.MarkDelivered(ctx, lease.Record.ID, lease.LeaseID); err != nil {
		// Delivery succeeded; lease release/mark failure is cleaned up by the
		// next worker after lease expiry (MarkDelivered is idempotent on state).
		return result, err
	}
	result.Delivered = true
	return result, nil
}

func (w *Worker) startHeartbeat(ctx context.Context, cancel context.CancelFunc, lease OutboxLease, result *ProcessResult) (<-chan error, <-chan struct{}) {
	errCh := make(chan error, 1)
	done := make(chan struct{})
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
				if _, err := w.outbox.Renew(ctx, lease.Record.ID, lease.LeaseID, w.lease); err != nil {
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

func (w *Worker) fail(ctx context.Context, lease OutboxLease, result ProcessResult, category, summary string, cause error) (ProcessResult, error) {
	attempt := lease.Record.Attempt
	if attempt <= 0 {
		attempt = 1
	}
	if attempt >= w.maxAttempts {
		if _, err := w.outbox.DeadLetter(ctx, lease.Record.ID, lease.LeaseID, category, summary); err != nil {
			return result, fmt.Errorf("%s: dead-letter: %w", summary, err)
		}
		result.DeadLettered = true
		return result, nil
	}
	next := w.now().UTC().Add(outboxRetryDelay(w.backoff, w.backoffMax, attempt, lease.Record.EventID, w.jitter))
	if _, err := w.outbox.Schedule(ctx, lease.Record.ID, lease.LeaseID, next, category, summary); err != nil {
		return result, fmt.Errorf("%s: schedule: %w", summary, err)
	}
	result.Scheduled = true
	_ = cause
	return result, nil
}

func outboxRetryDelay(base, max time.Duration, attempt int, eventID string, jitter float64) time.Duration {
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
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", eventID, attempt)))
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
