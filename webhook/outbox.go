package webhook

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/core"
)

// Outbox states for durable webhook delivery.
const (
	StatePending    = "pending"
	StateDelivered  = "delivered"
	StateDeadLetter = "dead_letter"
)

// OutboxRecord is one durable webhook delivery unit. Payload is the caller-safe
// audit event only; credentials and unrestricted bodies never enter the outbox.
type OutboxRecord struct {
	ID                  string
	EventID             string
	AuditStream         string
	Sequence            int64
	Event               audit.Event
	State               string
	Attempt             int
	NextAttemptAt       time.Time
	LeaseID             string
	LeaseOwner          string
	LeaseUntil          time.Time
	LastFailureCategory string
	LastFailureSummary  string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// OutboxLease is a time-bounded claim on one outbox record.
type OutboxLease struct {
	Record    OutboxRecord
	Owner     string
	LeaseID   string
	ExpiresAt time.Time
}

// Outbox persists webhook work until a worker delivers it. Implementations
// must treat Enqueue as idempotent on EventID so MultiSink retries and
// process restarts do not create duplicate delivery units.
type Outbox interface {
	Enqueue(context.Context, OutboxRecord) error
	Claim(context.Context, string, time.Duration) (OutboxLease, bool, error)
	Renew(context.Context, string, string, time.Duration) (time.Time, error)
	MarkDelivered(context.Context, string, string) error
	Schedule(context.Context, string, string, time.Time, string, string) (OutboxRecord, error)
	DeadLetter(context.Context, string, string, string, string) (OutboxRecord, error)
	Count(context.Context) (depth int64, oldest time.Time, err error)
	// Requeue moves a dead-lettered record back to pending after operator review.
	Requeue(context.Context, string, string) (OutboxRecord, error)
}

// MemoryOutbox is a process-local outbox for tests and single-node demos.
// It is not durable across restarts.
type MemoryOutbox struct {
	mu      sync.Mutex
	records map[string]OutboxRecord
	byEvent map[string]string
	now     func() time.Time
}

// NewMemoryOutbox constructs an empty in-process outbox.
func NewMemoryOutbox() *MemoryOutbox {
	return &MemoryOutbox{
		records: make(map[string]OutboxRecord),
		byEvent: make(map[string]string),
		now:     time.Now,
	}
}

// Enqueue stores a pending record. Duplicate EventID is a no-op success.
func (o *MemoryOutbox) Enqueue(_ context.Context, record OutboxRecord) error {
	if o == nil {
		return fmt.Errorf("%w: nil outbox", core.ErrInvalidArgument)
	}
	if strings.TrimSpace(record.EventID) == "" {
		record.EventID = strings.TrimSpace(record.Event.ID)
	}
	if strings.TrimSpace(record.EventID) == "" {
		return fmt.Errorf("%w: webhook outbox event id required", core.ErrInvalidArgument)
	}
	if strings.TrimSpace(record.Event.ID) == "" {
		record.Event.ID = record.EventID
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.byEvent[record.EventID]; ok {
		return nil
	}
	now := o.now().UTC()
	if record.ID == "" {
		record.ID = newEventID()
	}
	if record.State == "" {
		record.State = StatePending
	}
	record.CreatedAt = now
	record.UpdatedAt = now
	record.NextAttemptAt = time.Time{}
	o.records[record.ID] = cloneOutbox(record)
	o.byEvent[record.EventID] = record.ID
	return nil
}

// Claim leases one due pending record.
func (o *MemoryOutbox) Claim(_ context.Context, owner string, lease time.Duration) (OutboxLease, bool, error) {
	if o == nil || owner == "" || lease <= 0 {
		return OutboxLease{}, false, fmt.Errorf("%w: owner and lease required", core.ErrInvalidArgument)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now().UTC()
	var best *OutboxRecord
	for id, rec := range o.records {
		rec := rec
		if rec.State != StatePending {
			continue
		}
		if !rec.LeaseUntil.IsZero() && rec.LeaseUntil.After(now) {
			continue
		}
		if !rec.NextAttemptAt.IsZero() && rec.NextAttemptAt.After(now) {
			continue
		}
		if best == nil || outboxLess(rec, *best) {
			cp := rec
			cp.ID = id
			best = &cp
		}
	}
	if best == nil {
		return OutboxLease{}, false, nil
	}
	leaseID := newEventID()
	best.Attempt++
	best.LeaseID = leaseID
	best.LeaseOwner = owner
	best.LeaseUntil = now.Add(lease)
	best.UpdatedAt = now
	best.NextAttemptAt = time.Time{}
	o.records[best.ID] = cloneOutbox(*best)
	return OutboxLease{Record: cloneOutbox(*best), Owner: owner, LeaseID: leaseID, ExpiresAt: best.LeaseUntil}, true, nil
}

// Renew extends a live lease.
func (o *MemoryOutbox) Renew(_ context.Context, id, leaseID string, lease time.Duration) (time.Time, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	rec, ok := o.records[id]
	if !ok || rec.LeaseID != leaseID {
		return time.Time{}, fmt.Errorf("%w: webhook outbox lease is stale", core.ErrNotFound)
	}
	until := o.now().UTC().Add(lease)
	rec.LeaseUntil = until
	rec.UpdatedAt = o.now().UTC()
	o.records[id] = rec
	return until, nil
}

// MarkDelivered completes a leased record.
func (o *MemoryOutbox) MarkDelivered(_ context.Context, id, leaseID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	rec, ok := o.records[id]
	if !ok || rec.LeaseID != leaseID {
		return fmt.Errorf("%w: webhook outbox lease is stale", core.ErrNotFound)
	}
	rec.State = StateDelivered
	rec.LeaseID = ""
	rec.LeaseOwner = ""
	rec.LeaseUntil = time.Time{}
	rec.UpdatedAt = o.now().UTC()
	o.records[id] = rec
	return nil
}

// Schedule releases a lease and delays the next attempt.
func (o *MemoryOutbox) Schedule(_ context.Context, id, leaseID string, next time.Time, category, summary string) (OutboxRecord, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	rec, ok := o.records[id]
	if !ok || rec.LeaseID != leaseID {
		return OutboxRecord{}, fmt.Errorf("%w: webhook outbox lease is stale", core.ErrNotFound)
	}
	rec.State = StatePending
	rec.NextAttemptAt = next.UTC()
	rec.LastFailureCategory = category
	rec.LastFailureSummary = boundSummary(summary)
	rec.LeaseID = ""
	rec.LeaseOwner = ""
	rec.LeaseUntil = time.Time{}
	rec.UpdatedAt = o.now().UTC()
	o.records[id] = rec
	return cloneOutbox(rec), nil
}

// DeadLetter parks a record for operator review.
func (o *MemoryOutbox) DeadLetter(_ context.Context, id, leaseID, category, summary string) (OutboxRecord, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	rec, ok := o.records[id]
	if !ok || rec.LeaseID != leaseID {
		return OutboxRecord{}, fmt.Errorf("%w: webhook outbox lease is stale", core.ErrNotFound)
	}
	rec.State = StateDeadLetter
	rec.LastFailureCategory = category
	rec.LastFailureSummary = boundSummary(summary)
	rec.LeaseID = ""
	rec.LeaseOwner = ""
	rec.LeaseUntil = time.Time{}
	rec.NextAttemptAt = time.Time{}
	rec.UpdatedAt = o.now().UTC()
	o.records[id] = rec
	return cloneOutbox(rec), nil
}

// Count returns pending depth and oldest pending update time.
func (o *MemoryOutbox) Count(_ context.Context) (int64, time.Time, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var depth int64
	var oldest time.Time
	for _, rec := range o.records {
		if rec.State != StatePending {
			continue
		}
		depth++
		if oldest.IsZero() || rec.CreatedAt.Before(oldest) {
			oldest = rec.CreatedAt
		}
	}
	return depth, oldest, nil
}

// Requeue returns a dead-lettered record to pending.
func (o *MemoryOutbox) Requeue(_ context.Context, id, reason string) (OutboxRecord, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	rec, ok := o.records[id]
	if !ok || rec.State != StateDeadLetter {
		return OutboxRecord{}, fmt.Errorf("%w: webhook outbox record is not dead-lettered", core.ErrNotFound)
	}
	rec.State = StatePending
	rec.Attempt = 0
	rec.NextAttemptAt = time.Time{}
	rec.LastFailureCategory = "operator_requeue"
	rec.LastFailureSummary = boundSummary(reason)
	rec.UpdatedAt = o.now().UTC()
	o.records[id] = rec
	return cloneOutbox(rec), nil
}

func outboxLess(a, b OutboxRecord) bool {
	if a.AuditStream != b.AuditStream {
		return a.AuditStream < b.AuditStream
	}
	if a.Sequence != b.Sequence {
		return a.Sequence < b.Sequence
	}
	return a.CreatedAt.Before(b.CreatedAt)
}

func cloneOutbox(record OutboxRecord) OutboxRecord {
	// audit.Event contains maps; shallow copy is enough for store isolation of
	// scalars. Callers must not mutate Event maps after Enqueue.
	return record
}

func boundSummary(summary string) string {
	summary = strings.TrimSpace(summary)
	const max = 256
	if len(summary) > max {
		return summary[:max]
	}
	return summary
}
