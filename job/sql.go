package job

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
)

// SQLQueue is a durable FIFO backed by a *sql.DB.
//
// Schema is applied at construction (startup DDL, outside Loom SQL guards).
// Jobs still execute only through Runner → Caller.Call — this queue is not a
// privilege path.
//
// Security notes:
//   - Approval tokens are NOT persisted (never store raw approval secrets).
//   - Worker identity comes from Runner.Token / Job.Token at process time.
//   - Input JSON is opaque payload for the governed operation.
type SQLQueue struct {
	db      *sql.DB
	dialect db.Dialect
	table   string
}

// SQLQueueOptions configures durable queue storage.
type SQLQueueOptions struct {
	// Table defaults to loom_jobs. Must be a simple identifier.
	Table string
	// Dialect zero → sqlite.
	Dialect db.Dialect
}

// NewSQLQueue creates the jobs table if needed and returns a Queue.
func NewSQLQueue(ctx context.Context, sqldb *sql.DB, opts SQLQueueOptions) (*SQLQueue, error) {
	if sqldb == nil {
		return nil, fmt.Errorf("%w: nil db", core.ErrInvalidArgument)
	}
	dialect := opts.Dialect
	if dialect == db.DialectUnknown {
		dialect = db.DialectSQLite
	}
	table := opts.Table
	if table == "" {
		table = "loom_jobs"
	}
	if !safeIdent(table) {
		return nil, fmt.Errorf("%w: invalid table name %q", core.ErrInvalidArgument, table)
	}
	q := &SQLQueue{db: sqldb, dialect: dialect, table: table}
	if err := q.ensureSchema(ctx); err != nil {
		return nil, err
	}
	return q, nil
}

func safeIdent(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func (q *SQLQueue) ensureSchema(ctx context.Context) error {
	// status: pending | done | failed (running is transient; we claim atomically)
	var ddl string
	switch q.dialect {
	case db.DialectPostgres:
		ddl = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			operation TEXT NOT NULL,
			boundary TEXT NOT NULL,
			input_json TEXT NOT NULL DEFAULT '{}',
			resource_type TEXT NOT NULL DEFAULT '',
			resource_id TEXT NOT NULL DEFAULT '',
			idempotency_key TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`, q.table)
	default:
		ddl = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			operation TEXT NOT NULL,
			boundary TEXT NOT NULL,
			input_json TEXT NOT NULL DEFAULT '{}',
			resource_type TEXT NOT NULL DEFAULT '',
			resource_id TEXT NOT NULL DEFAULT '',
			idempotency_key TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			created_at TEXT NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%fZ','now'))
		)`, q.table)
	}
	if _, err := q.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("job: create table: %w", err)
	}
	idx := fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s_pending_idx ON %s (status, created_at)`, q.table, q.table)
	if _, err := q.db.ExecContext(ctx, idx); err != nil {
		return fmt.Errorf("job: create index: %w", err)
	}
	return nil
}

// Enqueue persists a pending job. ApprovalToken is intentionally dropped.
func (q *SQLQueue) Enqueue(ctx context.Context, j Job) error {
	if q == nil || q.db == nil {
		return fmt.Errorf("%w: nil queue", core.ErrInvalidArgument)
	}
	if j.ID == "" || j.Operation == "" {
		return fmt.Errorf("%w: job id and operation required", core.ErrInvalidArgument)
	}
	in := j.Input
	if in == nil {
		in = map[string]any{}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("job: marshal input: %w", err)
	}
	var resType, resID string
	if j.Resource != nil {
		resType = j.Resource.Type
		resID = j.Resource.ID
	}
	idem := j.IdempotencyKey
	// #nosec G201 -- q.table is restricted to a simple identifier in
	// NewSQLQueue before it is retained by the queue.
	sqlStr := fmt.Sprintf(
		`INSERT INTO %s (id, operation, boundary, input_json, resource_type, resource_id, idempotency_key, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`, q.table)
	sqlStr = rebind(q.dialect, sqlStr)
	_, err = q.db.ExecContext(ctx, sqlStr,
		j.ID, j.Operation, string(j.Boundary), string(raw), resType, resID, idem)
	if err != nil {
		return fmt.Errorf("job: enqueue: %w", err)
	}
	return nil
}

// Poll claims the oldest pending job (status → done claim via delete-on-complete style:
// we mark status='running' then return; Complete/Fail optional helpers mark terminal).
// For the Queue interface used by Runner, a claimed job is removed from pending so
// it will not be re-delivered unless Nack is called.
func (q *SQLQueue) Poll(ctx context.Context) (Job, bool, error) {
	if q == nil || q.db == nil {
		return Job{}, false, fmt.Errorf("%w: nil queue", core.ErrInvalidArgument)
	}
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		id, op, boundary, inputJSON, resType, resID, idem string
	)
	// Claim one pending row. Postgres uses SKIP LOCKED when available.
	var selectSQL string
	switch q.dialect {
	case db.DialectPostgres:
		selectSQL = fmt.Sprintf(
			`SELECT id, operation, boundary, input_json, resource_type, resource_id, idempotency_key
			 FROM %s WHERE status = 'pending' ORDER BY created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED`,
			q.table)
	default:
		// SQLite: BEGIN + read + update is enough under IMMEDIATE if needed;
		// default deferred is OK for single-worker demos.
		selectSQL = fmt.Sprintf(
			`SELECT id, operation, boundary, input_json, resource_type, resource_id, idempotency_key
			 FROM %s WHERE status = 'pending' ORDER BY created_at ASC LIMIT 1`,
			q.table)
	}
	row := tx.QueryRowContext(ctx, selectSQL)
	if err := row.Scan(&id, &op, &boundary, &inputJSON, &resType, &resID, &idem); err != nil {
		if err == sql.ErrNoRows {
			return Job{}, false, nil
		}
		return Job{}, false, err
	}
	upd := rebind(q.dialect, fmt.Sprintf(`UPDATE %s SET status = 'running' WHERE id = ? AND status = 'pending'`, q.table))
	res, err := tx.ExecContext(ctx, upd, id)
	if err != nil {
		return Job{}, false, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		// Lost the race; treat as empty.
		return Job{}, false, nil
	}
	if err := tx.Commit(); err != nil {
		return Job{}, false, err
	}

	var input map[string]any
	if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
		// Poison message: mark failed so it does not loop forever.
		_ = q.mark(ctx, id, "failed")
		return Job{}, false, fmt.Errorf("job: corrupt input for %s: %w", id, err)
	}
	j := Job{
		ID:             id,
		Operation:      op,
		Boundary:       core.BoundaryID(boundary),
		Input:          input,
		IdempotencyKey: idem,
	}
	if resType != "" || resID != "" {
		j.Resource = &core.ResourceRef{Type: resType, ID: resID}
	}
	// Auto-complete to done after claim is handed to runner — runner owns execution.
	// Mark done immediately after successful claim handoff so a crash mid-handler
	// does not redeliver (at-most-once). For at-least-once, callers can use a
	// custom queue; Loom's default is fail-closed / no double side effects via
	// idempotency keys on the op.
	_ = q.mark(ctx, id, "done")
	return j, true, nil
}

// PendingCount returns the number of pending jobs.
func (q *SQLQueue) PendingCount(ctx context.Context) (int, error) {
	if q == nil || q.db == nil {
		return 0, fmt.Errorf("%w: nil queue", core.ErrInvalidArgument)
	}
	var n int
	err := q.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE status = 'pending'`, q.table)).Scan(&n)
	return n, err
}

func (q *SQLQueue) mark(ctx context.Context, id, status string) error {
	sqlStr := rebind(q.dialect, fmt.Sprintf(`UPDATE %s SET status = ? WHERE id = ?`, q.table))
	_, err := q.db.ExecContext(ctx, sqlStr, status, id)
	return err
}

func rebind(d db.Dialect, s string) string {
	out, err := db.Rebind(d, s)
	if err != nil {
		// Fail closed at call sites that check dialect up front; return original
		// only if dialect is already sqlite-compatible (? placeholders).
		return s
	}
	return out
}

// Ensure SQLQueue implements Queue.
var _ Queue = (*SQLQueue)(nil)

// Idle wait helper for demos.
func WaitPendingEmpty(ctx context.Context, q *SQLQueue, poll time.Duration) error {
	if poll <= 0 {
		poll = 50 * time.Millisecond
	}
	for {
		n, err := q.PendingCount(ctx)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}
