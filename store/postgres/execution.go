package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/idempotency"
)

const defaultRecoveryLease = 5 * time.Minute
const defaultArchiveBatch = 1000

// ExecutionStore is the durable PostgreSQL implementation of
// execution.Store. Reconciliation is serialized per execution row and uses a
// revision predicate so a stale writer cannot overwrite a newer state.
type ExecutionStore struct {
	db *sql.DB
}

// NewExecutionStore wraps a migrated PostgreSQL pool.
func NewExecutionStore(db *sql.DB) *ExecutionStore {
	return &ExecutionStore{db: db}
}

// Durable reports that execution records survive process restart and can be
// shared by multiple application replicas.
func (s *ExecutionStore) Durable() bool { return s != nil && s.db != nil }

type rowScanner interface {
	Scan(...any) error
}

func scanExecutionRecord(row rowScanner) (execution.Record, int64, string, time.Time, error) {
	var (
		record      execution.Record
		responseRaw []byte
		revision    int64
		leaseID     sql.NullString
		leaseOwner  sql.NullString
		leaseUntil  sql.NullTime
	)
	err := row.Scan(
		&record.ExecutionID,
		&record.Operation,
		&record.OperationVersion,
		&record.Principal,
		&record.Boundary,
		&record.Outcome,
		&record.State,
		&responseRaw,
		&record.IdempotencyKey,
		&record.Fingerprint,
		&record.RecoveryQueued,
		&record.ReconciliationNote,
		&record.StartedAt,
		&record.UpdatedAt,
		&revision,
		&leaseID,
		&leaseOwner,
		&leaseUntil,
	)
	if err != nil {
		return execution.Record{}, 0, "", time.Time{}, err
	}
	if err := json.Unmarshal(responseRaw, &record.Response); err != nil {
		return execution.Record{}, 0, "", time.Time{}, fmt.Errorf("postgres execution: corrupt response: %w", err)
	}
	if record.ExecutionID == "" || record.OperationVersion == "" || record.State == "" {
		return execution.Record{}, 0, "", time.Time{}, fmt.Errorf("postgres execution: invalid stored record")
	}
	if !leaseUntil.Valid {
		leaseUntil.Time = time.Time{}
	}
	return record, revision, leaseOwner.String, leaseUntil.Time, nil
}

const executionColumns = `
    execution_id, operation, operation_version, principal, boundary,
    outcome, state, response, idempotency_key, fingerprint,
    recovery_queued, reconciliation_note, started_at, updated_at, revision,
    recovery_lease_id, recovery_lease_owner, recovery_lease_until`

func validateExecutionRecord(record execution.Record) error {
	if record.ExecutionID == "" || record.OperationVersion == "" || record.State == "" {
		return fmt.Errorf("%w: execution record requires id, operation version, and state", core.ErrInvalidArgument)
	}
	return nil
}

// Put inserts or replaces a record atomically. Replacing a record increments
// its revision and clears any old recovery lease; queue state comes from the
// supplied record.
func (s *ExecutionStore) Put(ctx context.Context, record execution.Record) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: nil execution store", core.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateExecutionRecord(record); err != nil {
		return err
	}
	if record.StartedAt.IsZero() {
		record.StartedAt = time.Now().UTC()
	}
	record.UpdatedAt = time.Now().UTC()
	responseRaw, err := json.Marshal(record.Response)
	if err != nil {
		return fmt.Errorf("postgres execution: marshal response: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO loom_executions (`+executionColumns+`)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,1,NULL,NULL,NULL)
        ON CONFLICT (execution_id) DO UPDATE SET
            operation = EXCLUDED.operation,
            operation_version = EXCLUDED.operation_version,
            principal = EXCLUDED.principal,
            boundary = EXCLUDED.boundary,
            outcome = EXCLUDED.outcome,
            state = EXCLUDED.state,
            response = EXCLUDED.response,
            idempotency_key = EXCLUDED.idempotency_key,
            fingerprint = EXCLUDED.fingerprint,
            recovery_queued = EXCLUDED.recovery_queued,
            reconciliation_note = EXCLUDED.reconciliation_note,
            started_at = EXCLUDED.started_at,
            updated_at = EXCLUDED.updated_at,
            revision = loom_executions.revision + 1,
            recovery_lease_id = NULL,
            recovery_lease_owner = NULL,
            recovery_lease_until = NULL
    `,
		record.ExecutionID, record.Operation, record.OperationVersion, record.Principal,
		record.Boundary, record.Outcome, record.State, responseRaw, record.IdempotencyKey,
		record.Fingerprint, record.RecoveryQueued, record.ReconciliationNote,
		record.StartedAt.UTC(), record.UpdatedAt.UTC(),
	)
	return err
}

// Get returns a fresh record decoded from PostgreSQL JSON, so the caller
// cannot mutate the stored response through a shared map.
func (s *ExecutionStore) Get(ctx context.Context, id string) (execution.Record, bool, error) {
	if s == nil || s.db == nil || id == "" {
		return execution.Record{}, false, fmt.Errorf("%w: execution id required", core.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return execution.Record{}, false, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+executionColumns+` FROM loom_executions WHERE execution_id = $1`, id)
	record, _, _, _, err := scanExecutionRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return execution.Record{}, false, nil
	}
	if err != nil {
		return execution.Record{}, false, err
	}
	return record, true, nil
}

// Reconcile is idempotent for a repeated confirmation. A contradictory
// confirmation is rejected and cannot overwrite the first durable outcome.
func (s *ExecutionStore) Reconcile(ctx context.Context, id string, outcome core.Outcome, note string) (execution.Record, error) {
	if s == nil || s.db == nil {
		return execution.Record{}, fmt.Errorf("%w: nil execution store", core.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return execution.Record{}, err
	}
	if outcome != core.OutcomeAllowed && outcome != core.OutcomeDenied {
		return execution.Record{}, fmt.Errorf("%w: reconciliation outcome must be allowed or denied", core.ErrInvalidArgument)
	}
	// READ COMMITTED plus SELECT FOR UPDATE lets a concurrent confirmer wait
	// for the first writer and then observe the durable reconciled state. The
	// revision predicate still protects the update if the storage layer changes.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return execution.Record{}, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, `SELECT `+executionColumns+` FROM loom_executions WHERE execution_id = $1 FOR UPDATE`, id)
	record, revision, _, _, err := scanExecutionRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return execution.Record{}, fmt.Errorf("%w: execution %s", core.ErrNotFound, id)
	}
	if err != nil {
		return execution.Record{}, err
	}
	if record.State == execution.StateReconciled {
		if record.Outcome != outcome {
			return execution.Record{}, fmt.Errorf("%w: execution %s already reconciled with outcome %s", core.ErrAlreadyExists, id, record.Outcome)
		}
		if err := tx.Commit(); err != nil {
			return execution.Record{}, err
		}
		return record, nil
	}
	if record.State != execution.StateExecutedUnconfirmed {
		return execution.Record{}, fmt.Errorf("execution: %s is not awaiting reconciliation", id)
	}
	record.Outcome = outcome
	record.State = execution.StateReconciled
	record.Response.Outcome = outcome
	record.Response.Allowed = outcome == core.OutcomeAllowed
	record.Response.ReliabilityWarning = ""
	record.ReconciliationNote = note
	record.UpdatedAt = time.Now().UTC()
	responseRaw, err := json.Marshal(record.Response)
	if err != nil {
		return execution.Record{}, fmt.Errorf("postgres execution: marshal response: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
        UPDATE loom_executions
        SET outcome = $2, state = $3, response = $4,
            reconciliation_note = $5, updated_at = $6, revision = revision + 1
        WHERE execution_id = $1 AND revision = $7
    `, id, record.Outcome, record.State, responseRaw, note, record.UpdatedAt.UTC(), revision)
	if err != nil {
		return execution.Record{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return execution.Record{}, fmt.Errorf("%w: stale execution revision", core.ErrAlreadyExists)
	}
	if err := tx.Commit(); err != nil {
		return execution.Record{}, err
	}
	return record, nil
}

// MarkRecoveryQueued durably exposes that asynchronous recording work exists.
func (s *ExecutionStore) MarkRecoveryQueued(ctx context.Context, id string) (execution.Record, error) {
	if s == nil || s.db == nil {
		return execution.Record{}, fmt.Errorf("%w: nil execution store", core.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return execution.Record{}, err
	}
	result, err := s.db.ExecContext(ctx, `
        UPDATE loom_executions
        SET recovery_queued = TRUE, updated_at = NOW(), revision = revision + 1
        WHERE execution_id = $1
    `, id)
	if err != nil {
		return execution.Record{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return execution.Record{}, fmt.Errorf("%w: execution %s", core.ErrNotFound, id)
	}
	record, ok, err := s.Get(ctx, id)
	if err != nil {
		return execution.Record{}, err
	}
	if !ok {
		return execution.Record{}, fmt.Errorf("%w: execution %s", core.ErrNotFound, id)
	}
	return record, nil
}

// Enqueue implements idempotency.RecoveryQueue. The completion payload is
// stored on the execution row before the queue marker is set, so a recovery
// worker can claim one complete, durable record without reading a second
// backend.
func (s *ExecutionStore) Enqueue(ctx context.Context, recovery idempotency.RecoveryRecord) error {
	if s == nil || s.db == nil || recovery.ExecutionID == "" || recovery.Key == "" || recovery.Fingerprint == "" {
		return fmt.Errorf("%w: recovery execution, key, and fingerprint required", core.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	responseRaw, err := json.Marshal(recovery.Response)
	if err != nil {
		return fmt.Errorf("postgres execution: marshal recovery response: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `
        UPDATE loom_executions
        SET idempotency_key = $2, fingerprint = $3, response = $4,
            recovery_queued = TRUE, updated_at = NOW(), revision = revision + 1
        WHERE execution_id = $1
    `, recovery.ExecutionID, recovery.Key, recovery.Fingerprint, responseRaw)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return fmt.Errorf("%w: execution %s", core.ErrNotFound, recovery.ExecutionID)
	}
	return nil
}

func newLeaseID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("postgres execution: lease id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// ClaimRecovery atomically claims one queued record for owner. SKIP LOCKED
// lets multiple workers drain the queue without duplicate live leases.
func (s *ExecutionStore) ClaimRecovery(ctx context.Context, owner string, lease time.Duration) (execution.RecoveryLease, bool, error) {
	if s == nil || s.db == nil || owner == "" {
		return execution.RecoveryLease{}, false, fmt.Errorf("%w: recovery owner and store required", core.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return execution.RecoveryLease{}, false, err
	}
	if lease <= 0 {
		lease = defaultRecoveryLease
	}
	leaseID, err := newLeaseID()
	if err != nil {
		return execution.RecoveryLease{}, false, err
	}
	expires := time.Now().UTC().Add(lease)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return execution.RecoveryLease{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	row := tx.QueryRowContext(ctx, `
        SELECT `+executionColumns+`
        FROM loom_executions
        WHERE recovery_queued = TRUE
          AND (recovery_lease_until IS NULL OR recovery_lease_until <= NOW())
        ORDER BY updated_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    `)
	record, revision, _, _, err := scanExecutionRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return execution.RecoveryLease{}, false, nil
	}
	if err != nil {
		return execution.RecoveryLease{}, false, err
	}
	result, err := tx.ExecContext(ctx, `
        UPDATE loom_executions
        SET recovery_lease_id = $2, recovery_lease_owner = $3,
            recovery_lease_until = $4, updated_at = NOW(), revision = revision + 1
        WHERE execution_id = $1 AND revision = $5
    `, record.ExecutionID, leaseID, owner, expires, revision)
	if err != nil {
		return execution.RecoveryLease{}, false, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return execution.RecoveryLease{}, false, fmt.Errorf("%w: recovery claim lost", core.ErrAlreadyExists)
	}
	if err := tx.Commit(); err != nil {
		return execution.RecoveryLease{}, false, err
	}
	record.UpdatedAt = time.Now().UTC()
	return execution.RecoveryLease{Record: record, Owner: owner, LeaseID: leaseID, ExpiresAt: expires}, true, nil
}

// ReleaseRecovery releases a lease. completed removes the item from the
// recovery queue; false makes it immediately claimable again.
func (s *ExecutionStore) ReleaseRecovery(ctx context.Context, id, leaseID string, completed bool) error {
	if s == nil || s.db == nil || id == "" || leaseID == "" {
		return fmt.Errorf("%w: execution id and lease id required", core.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
        UPDATE loom_executions
        SET recovery_queued = CASE WHEN $3 THEN FALSE ELSE recovery_queued END,
            recovery_lease_id = NULL, recovery_lease_owner = NULL,
            recovery_lease_until = NULL, updated_at = NOW(), revision = revision + 1
        WHERE execution_id = $1 AND recovery_lease_id = $2
    `, id, leaseID, completed)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return fmt.Errorf("%w: recovery lease is missing or owned by another worker", core.ErrNotFound)
	}
	return nil
}

// RecoveryOwner returns the current recovery lease owner and expiry.
func (s *ExecutionStore) RecoveryOwner(ctx context.Context, id string) (string, time.Time, bool, error) {
	if s == nil || s.db == nil || id == "" {
		return "", time.Time{}, false, fmt.Errorf("%w: execution id required", core.ErrInvalidArgument)
	}
	var owner sql.NullString
	var until sql.NullTime
	err := s.db.QueryRowContext(ctx, `
        SELECT recovery_lease_owner, recovery_lease_until
        FROM loom_executions WHERE execution_id = $1
    `, id).Scan(&owner, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, err
	}
	if !owner.Valid || owner.String == "" {
		return "", time.Time{}, false, nil
	}
	return owner.String, until.Time, true, nil
}

// Archive moves old terminal records to the archive table in one transaction.
// Recovery-queued and non-terminal records are never moved.
func (s *ExecutionStore) Archive(ctx context.Context, before time.Time, limit int) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("%w: nil execution store", core.ErrInvalidArgument)
	}
	if before.IsZero() {
		return 0, fmt.Errorf("%w: retention cutoff required", core.ErrInvalidArgument)
	}
	if limit <= 0 {
		limit = defaultArchiveBatch
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
        SELECT execution_id
        FROM loom_executions
        WHERE updated_at < $1
          AND recovery_queued = FALSE
          AND state IN ('allowed', 'denied', 'reconciled')
        ORDER BY updated_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT $2
    `, before.UTC(), limit)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	var archived int64
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO loom_execution_archive (`+executionColumns+`)
            SELECT `+executionColumns+` FROM loom_executions
            WHERE execution_id = $1
            ON CONFLICT (execution_id) DO NOTHING
        `, id); err != nil {
			return 0, err
		}
		result, err := tx.ExecContext(ctx, `
            DELETE FROM loom_executions
            WHERE execution_id = $1
              AND recovery_queued = FALSE
              AND state IN ('allowed', 'denied', 'reconciled')
        `, id)
		if err != nil {
			return 0, err
		}
		count, _ := result.RowsAffected()
		archived += count
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return archived, nil
}

// Purge removes terminal records older than before from the live table.
// Call Archive first when retention requires a durable historical copy.
func (s *ExecutionStore) Purge(ctx context.Context, before time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("%w: nil execution store", core.ErrInvalidArgument)
	}
	if before.IsZero() {
		return 0, fmt.Errorf("%w: retention cutoff required", core.ErrInvalidArgument)
	}
	result, err := s.db.ExecContext(ctx, `
    DELETE FROM loom_executions
        WHERE updated_at < $1
          AND recovery_queued = FALSE
          AND state IN ('allowed', 'denied', 'reconciled')
    `, before.UTC())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

var _ execution.Store = (*ExecutionStore)(nil)
var _ execution.RecoveryQueue = (*ExecutionStore)(nil)
var _ idempotency.RecoveryQueue = (*ExecutionStore)(nil)
