package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/webhook"
)

// WebhookOutbox is the PostgreSQL durable webhook delivery queue.
type WebhookOutbox struct {
	db *sql.DB
}

// NewWebhookOutbox binds an outbox to a shared pool.
func NewWebhookOutbox(db *sql.DB) *WebhookOutbox {
	return &WebhookOutbox{db: db}
}

// Enqueue inserts a pending delivery unit. Duplicate event_id is success.
func (o *WebhookOutbox) Enqueue(ctx context.Context, record webhook.OutboxRecord) error {
	if o == nil || o.db == nil {
		return fmt.Errorf("%w: nil webhook outbox", core.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return err
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
	if record.ID == "" {
		id, err := newOutboxID()
		if err != nil {
			return err
		}
		record.ID = id
	}
	payload, err := json.Marshal(record.Event)
	if err != nil {
		return fmt.Errorf("postgres webhook outbox: marshal: %w", err)
	}
	now := time.Now().UTC()
	_, err = o.db.ExecContext(ctx, `
		INSERT INTO loom_webhook_outbox (
			id, event_id, audit_stream, sequence_no, payload, state,
			attempt, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,'pending',0,$6,$6)
		ON CONFLICT (event_id) DO NOTHING
	`, record.ID, record.EventID, record.AuditStream, record.Sequence, payload, now)
	return err
}

// Claim leases one due pending record using SKIP LOCKED.
func (o *WebhookOutbox) Claim(ctx context.Context, owner string, lease time.Duration) (webhook.OutboxLease, bool, error) {
	if o == nil || o.db == nil || owner == "" {
		return webhook.OutboxLease{}, false, fmt.Errorf("%w: owner and store required", core.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return webhook.OutboxLease{}, false, err
	}
	if lease <= 0 {
		lease = 30 * time.Second
	}
	leaseID, err := newOutboxID()
	if err != nil {
		return webhook.OutboxLease{}, false, err
	}
	expires := time.Now().UTC().Add(lease)
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return webhook.OutboxLease{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, `
		SELECT id, event_id, audit_stream, sequence_no, payload, state, attempt,
		       next_attempt_at, last_failure_category, last_failure_summary,
		       created_at, updated_at
		FROM loom_webhook_outbox
		WHERE state = 'pending'
		  AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
		  AND (lease_until IS NULL OR lease_until <= NOW())
		ORDER BY audit_stream ASC, sequence_no ASC, created_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`)
	record, err := scanOutbox(row)
	if errors.Is(err, sql.ErrNoRows) {
		return webhook.OutboxLease{}, false, nil
	}
	if err != nil {
		return webhook.OutboxLease{}, false, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE loom_webhook_outbox
		SET lease_id = $2, lease_owner = $3, lease_until = $4,
		    attempt = attempt + 1, next_attempt_at = NULL, updated_at = NOW()
		WHERE id = $1
	`, record.ID, leaseID, owner, expires)
	if err != nil {
		return webhook.OutboxLease{}, false, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return webhook.OutboxLease{}, false, fmt.Errorf("%w: webhook outbox claim lost", core.ErrAlreadyExists)
	}
	if err := tx.Commit(); err != nil {
		return webhook.OutboxLease{}, false, err
	}
	record.Attempt++
	record.LeaseID = leaseID
	record.LeaseOwner = owner
	record.LeaseUntil = expires
	return webhook.OutboxLease{Record: record, Owner: owner, LeaseID: leaseID, ExpiresAt: expires}, true, nil
}

// Renew extends a live lease.
func (o *WebhookOutbox) Renew(ctx context.Context, id, leaseID string, lease time.Duration) (time.Time, error) {
	if o == nil || o.db == nil || id == "" || leaseID == "" {
		return time.Time{}, fmt.Errorf("%w: id and lease id required", core.ErrInvalidArgument)
	}
	if lease <= 0 {
		lease = 30 * time.Second
	}
	expires := time.Now().UTC().Add(lease)
	result, err := o.db.ExecContext(ctx, `
		UPDATE loom_webhook_outbox
		SET lease_until = $3, updated_at = NOW()
		WHERE id = $1 AND lease_id = $2 AND state = 'pending' AND lease_until > NOW()
	`, id, leaseID, expires)
	if err != nil {
		return time.Time{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return time.Time{}, fmt.Errorf("%w: webhook outbox lease is stale", core.ErrNotFound)
	}
	return expires, nil
}

// MarkDelivered completes delivery under the live lease.
func (o *WebhookOutbox) MarkDelivered(ctx context.Context, id, leaseID string) error {
	if o == nil || o.db == nil || id == "" || leaseID == "" {
		return fmt.Errorf("%w: id and lease id required", core.ErrInvalidArgument)
	}
	result, err := o.db.ExecContext(ctx, `
		UPDATE loom_webhook_outbox
		SET state = 'delivered', lease_id = NULL, lease_owner = NULL,
		    lease_until = NULL, next_attempt_at = NULL, updated_at = NOW()
		WHERE id = $1 AND lease_id = $2
	`, id, leaseID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		// Already delivered under a previous attempt is acceptable when the
		// lease was lost after a successful HTTP POST.
		var state string
		err := o.db.QueryRowContext(ctx, `SELECT state FROM loom_webhook_outbox WHERE id = $1`, id).Scan(&state)
		if err == nil && state == webhook.StateDelivered {
			return nil
		}
		return fmt.Errorf("%w: webhook outbox lease is stale", core.ErrNotFound)
	}
	return nil
}

// Schedule delays the next attempt and releases the lease.
func (o *WebhookOutbox) Schedule(ctx context.Context, id, leaseID string, next time.Time, category, summary string) (webhook.OutboxRecord, error) {
	if o == nil || o.db == nil || id == "" || leaseID == "" || next.IsZero() {
		return webhook.OutboxRecord{}, fmt.Errorf("%w: schedule arguments required", core.ErrInvalidArgument)
	}
	result, err := o.db.ExecContext(ctx, `
		UPDATE loom_webhook_outbox
		SET next_attempt_at = $3, last_failure_category = $4, last_failure_summary = $5,
		    lease_id = NULL, lease_owner = NULL, lease_until = NULL, updated_at = NOW()
		WHERE id = $1 AND lease_id = $2 AND state = 'pending'
	`, id, leaseID, next.UTC(), category, boundOutboxSummary(summary))
	if err != nil {
		return webhook.OutboxRecord{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return webhook.OutboxRecord{}, fmt.Errorf("%w: webhook outbox lease is stale", core.ErrNotFound)
	}
	return o.get(ctx, id)
}

// DeadLetter parks a record for operator review.
func (o *WebhookOutbox) DeadLetter(ctx context.Context, id, leaseID, category, summary string) (webhook.OutboxRecord, error) {
	if o == nil || o.db == nil || id == "" || leaseID == "" {
		return webhook.OutboxRecord{}, fmt.Errorf("%w: dead-letter arguments required", core.ErrInvalidArgument)
	}
	result, err := o.db.ExecContext(ctx, `
		UPDATE loom_webhook_outbox
		SET state = 'dead_letter', last_failure_category = $3, last_failure_summary = $4,
		    lease_id = NULL, lease_owner = NULL, lease_until = NULL,
		    next_attempt_at = NULL, updated_at = NOW()
		WHERE id = $1 AND lease_id = $2 AND state = 'pending'
	`, id, leaseID, category, boundOutboxSummary(summary))
	if err != nil {
		return webhook.OutboxRecord{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return webhook.OutboxRecord{}, fmt.Errorf("%w: webhook outbox lease is stale", core.ErrNotFound)
	}
	return o.get(ctx, id)
}

// Count reports pending depth and oldest created_at.
func (o *WebhookOutbox) Count(ctx context.Context) (int64, time.Time, error) {
	if o == nil || o.db == nil {
		return 0, time.Time{}, fmt.Errorf("%w: nil webhook outbox", core.ErrInvalidArgument)
	}
	var depth int64
	var oldest sql.NullTime
	err := o.db.QueryRowContext(ctx, `
		SELECT COUNT(*), MIN(created_at)
		FROM loom_webhook_outbox
		WHERE state = 'pending'
	`).Scan(&depth, &oldest)
	if err != nil {
		return 0, time.Time{}, err
	}
	if !oldest.Valid {
		return depth, time.Time{}, nil
	}
	return depth, oldest.Time.UTC(), nil
}

// Requeue moves a dead-lettered record back to pending.
func (o *WebhookOutbox) Requeue(ctx context.Context, id, reason string) (webhook.OutboxRecord, error) {
	if o == nil || o.db == nil || strings.TrimSpace(id) == "" {
		return webhook.OutboxRecord{}, fmt.Errorf("%w: id required", core.ErrInvalidArgument)
	}
	result, err := o.db.ExecContext(ctx, `
		UPDATE loom_webhook_outbox
		SET state = 'pending', attempt = 0, next_attempt_at = NULL,
		    last_failure_category = 'operator_requeue', last_failure_summary = $2,
		    lease_id = NULL, lease_owner = NULL, lease_until = NULL, updated_at = NOW()
		WHERE id = $1 AND state = 'dead_letter'
	`, id, boundOutboxSummary(reason))
	if err != nil {
		return webhook.OutboxRecord{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return webhook.OutboxRecord{}, fmt.Errorf("%w: webhook outbox record is not dead-lettered", core.ErrNotFound)
	}
	return o.get(ctx, id)
}

func (o *WebhookOutbox) get(ctx context.Context, id string) (webhook.OutboxRecord, error) {
	row := o.db.QueryRowContext(ctx, `
		SELECT id, event_id, audit_stream, sequence_no, payload, state, attempt,
		       next_attempt_at, last_failure_category, last_failure_summary,
		       created_at, updated_at
		FROM loom_webhook_outbox WHERE id = $1
	`, id)
	return scanOutbox(row)
}

type outboxScanner interface {
	Scan(dest ...any) error
}

func scanOutbox(row outboxScanner) (webhook.OutboxRecord, error) {
	var (
		record  webhook.OutboxRecord
		payload []byte
		next    sql.NullTime
	)
	err := row.Scan(
		&record.ID, &record.EventID, &record.AuditStream, &record.Sequence, &payload,
		&record.State, &record.Attempt, &next, &record.LastFailureCategory, &record.LastFailureSummary,
		&record.CreatedAt, &record.UpdatedAt,
	)
	if err != nil {
		return webhook.OutboxRecord{}, err
	}
	if next.Valid {
		record.NextAttemptAt = next.Time.UTC()
	}
	var event audit.Event
	if err := json.Unmarshal(payload, &event); err != nil {
		return webhook.OutboxRecord{}, fmt.Errorf("postgres webhook outbox: payload: %w", err)
	}
	record.Event = event
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func newOutboxID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("postgres webhook outbox: id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func boundOutboxSummary(summary string) string {
	summary = strings.TrimSpace(summary)
	if len(summary) > 256 {
		return summary[:256]
	}
	return summary
}
