package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/core"
)

// DefaultAuditStream preserves the original single-stream constructor. Shared
// deployments should use a named stream for each independent audit sequence.
const DefaultAuditStream = "default"

// AuditSink persists audit events to PostgreSQL and coordinates one hash-chain
// head per named stream. The row lock makes sequence assignment and previous
// hash verification safe across Loom replicas.
type AuditSink struct {
	db       *sql.DB
	streamID string
}

// Durable reports that audit records are persisted in PostgreSQL.
func (s *AuditSink) Durable() bool { return s != nil && s.db != nil && s.streamID != "" }

// NewAuditSink wraps db using the compatibility stream named "default".
func NewAuditSink(db *sql.DB) *AuditSink {
	return NewAuditSinkForStream(db, DefaultAuditStream)
}

// NewAuditSinkForStream creates a coordinated sink for one named audit stream.
// All replicas writing the same stream must use the same stream ID.
func NewAuditSinkForStream(db *sql.DB, streamID string) *AuditSink {
	return &AuditSink{db: db, streamID: strings.TrimSpace(streamID)}
}

// StreamID returns the configured durable stream name.
func (s *AuditSink) StreamID() string {
	if s == nil {
		return ""
	}
	return s.streamID
}

// Write assigns a sequence and hash under the stream-head row lock, then
// inserts the event and advances the head in one transaction.
func (s *AuditSink) Write(ctx context.Context, ev audit.Event) error {
	if s == nil || s.db == nil || s.streamID == "" {
		return fmt.Errorf("%w: audit sink or stream is not configured", core.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	ev, headHash, nextSequence, checkpointID, err := s.assignChain(ctx, tx, ev)
	if err != nil {
		return err
	}
	if err := insertAuditEvent(ctx, tx, ev); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE loom_audit_chain_heads
		SET next_sequence = $2 + 1, head_hash = $3, updated_at = NOW()
		WHERE stream_id = $1 AND next_sequence = $2 AND head_hash = $4
	`, s.streamID, nextSequence, ev.EventHash, headHash)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return fmt.Errorf("audit: chain head changed while inserting stream %q", s.streamID)
	}
	_ = checkpointID // retained in the event and head for explicit rotation.
	return tx.Commit()
}

func (s *AuditSink) assignChain(ctx context.Context, tx *sql.Tx, ev audit.Event) (audit.Event, string, int64, string, error) {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO loom_audit_chain_heads (stream_id, next_sequence, head_hash, checkpoint_id, updated_at)
		VALUES ($1, 1, '', '', NOW())
		ON CONFLICT (stream_id) DO NOTHING
	`, s.streamID); err != nil {
		return audit.Event{}, "", 0, "", err
	}
	var nextSequence int64
	var headHash, checkpointID string
	if err := tx.QueryRowContext(ctx, `
		SELECT next_sequence, head_hash, checkpoint_id
		FROM loom_audit_chain_heads
		WHERE stream_id = $1
		FOR UPDATE
	`, s.streamID).Scan(&nextSequence, &headHash, &checkpointID); err != nil {
		return audit.Event{}, "", 0, "", err
	}
	if nextSequence <= 0 {
		return audit.Event{}, "", 0, "", fmt.Errorf("audit: invalid next sequence for stream %q", s.streamID)
	}
	if ev.AuditStream != "" && ev.AuditStream != s.streamID {
		return audit.Event{}, "", 0, "", fmt.Errorf("audit: event stream %q does not match sink stream %q", ev.AuditStream, s.streamID)
	}
	if ev.PrevEventHash != "" && ev.PrevEventHash != headHash {
		return audit.Event{}, "", 0, "", fmt.Errorf("audit: previous hash does not match stream %q head", s.streamID)
	}
	if ev.CheckpointID != "" && checkpointID != "" && ev.CheckpointID != checkpointID {
		return audit.Event{}, "", 0, "", fmt.Errorf("audit: checkpoint %q is not active for stream %q", ev.CheckpointID, s.streamID)
	}
	ev.AuditStream = s.streamID
	ev.Sequence = nextSequence
	ev.PrevEventHash = headHash
	ev.CheckpointID = checkpointID
	ev.EventHash = ""
	hash, err := audit.HashEvent(ev)
	if err != nil {
		return audit.Event{}, "", 0, "", err
	}
	ev.EventHash = hash
	return ev, headHash, nextSequence, checkpointID, nil
}

func insertAuditEvent(ctx context.Context, tx *sql.Tx, ev audit.Event) error {
	inRaw, err := json.Marshal(ev.Input)
	if err != nil {
		inRaw = []byte("null")
	}
	mdRaw, err := json.Marshal(ev.Metadata)
	if err != nil {
		mdRaw = []byte("null")
	}
	effectsRaw, err := json.Marshal(ev.Effects)
	if err != nil {
		effectsRaw = []byte("null")
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO loom_audit (
			id, schema_version, event_type, ts, execution_id, trace_id,
			protocol_version, decision, outcome, reason, step, message,
			principal, delegator, boundary, boundary_type, boundary_parent_type,
			boundary_parent_id, tenant_id, operation, operation_version, resource,
			resource_type, resource_id, effects, risk, input, input_digest,
			output_digest, output_field_count, requested_field_count, metadata,
			duration_ms, auth_method, idempotency_key_digest, idempotency_state,
			approval_state, quota_state, reliability_warning, adapter, prior_audit_id,
			execution_state, execution_revision, recovery_queued, reconciliation_note,
			prev_event_hash, event_hash, audit_stream, sequence_no, checkpoint_id
		) VALUES (
			$1,$2,$3,$4,$5,$6,
			$7,$8,$9,$10,$11,$12,
			$13,$14,$15,$16,$17,
			$18,$19,$20,$21,$22,
			$23,$24,$25,$26,$27,$28,
			$29,$30,$31,$32,$33,$34,
			$35,$36,$37,$38,$39,$40,$41,
			$42,$43,$44,$45,$46,$47,$48,$49,$50
		)
		ON CONFLICT (id) DO NOTHING
	`,
		ev.ID, ev.SchemaVersion, ev.EventType, ev.Timestamp.UTC(), ev.ExecutionID, ev.TraceID,
		ev.ProtocolVersion, ev.Decision, ev.Outcome, ev.Reason, ev.Step, ev.Message,
		ev.Principal, ev.Delegator, ev.Boundary, ev.BoundaryType, ev.BoundaryParentType,
		ev.BoundaryParentID, ev.TenantID, ev.Operation, ev.OperationVersion, ev.Resource,
		ev.ResourceType, ev.ResourceID, effectsRaw, ev.Risk, inRaw, ev.InputDigest,
		ev.OutputDigest, ev.OutputFieldCount, ev.RequestedFieldCount, mdRaw, ev.DurationMS,
		ev.AuthMethod, ev.IdempotencyKeyDigest, ev.IdempotencyState, ev.ApprovalState,
		ev.QuotaState, ev.ReliabilityWarning, ev.Adapter, ev.PriorAuditID,
		ev.ExecutionState, ev.ExecutionRevision, ev.RecoveryQueued, ev.ReconciliationNote,
		ev.PrevEventHash, ev.EventHash, ev.AuditStream, ev.Sequence, ev.CheckpointID,
	)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return fmt.Errorf("%w: audit event %s already exists", core.ErrAlreadyExists, ev.ID)
	}
	return nil
}

// RotateStream changes the active checkpoint identifier without resetting the
// sequence. expectedHeadHash may be supplied to prevent rotating a stale head.
func (s *AuditSink) RotateStream(ctx context.Context, streamID, checkpointID, expectedHeadHash string) error {
	if s == nil || s.db == nil || strings.TrimSpace(streamID) == "" || strings.TrimSpace(checkpointID) == "" {
		return fmt.Errorf("%w: stream and checkpoint are required", core.ErrInvalidArgument)
	}
	streamID = strings.TrimSpace(streamID)
	checkpointID = strings.TrimSpace(checkpointID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO loom_audit_chain_heads (stream_id, next_sequence, head_hash, checkpoint_id, updated_at)
		VALUES ($1, 1, '', '', NOW())
		ON CONFLICT (stream_id) DO NOTHING
	`, streamID); err != nil {
		return err
	}
	var headHash string
	if err := tx.QueryRowContext(ctx, `SELECT head_hash FROM loom_audit_chain_heads WHERE stream_id = $1 FOR UPDATE`, streamID).Scan(&headHash); err != nil {
		return err
	}
	if expectedHeadHash != "" && expectedHeadHash != headHash {
		return fmt.Errorf("audit: stream %q head changed before rotation", streamID)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE loom_audit_chain_heads SET checkpoint_id = $2, updated_at = NOW() WHERE stream_id = $1`, streamID, checkpointID); err != nil {
		return err
	}
	return tx.Commit()
}

// ChainHead returns the current durable head for a named stream.
func (s *AuditSink) ChainHead(ctx context.Context, streamID string) (int64, string, string, error) {
	if s == nil || s.db == nil || strings.TrimSpace(streamID) == "" {
		return 0, "", "", fmt.Errorf("%w: stream is required", core.ErrInvalidArgument)
	}
	var nextSequence int64
	var headHash, checkpointID string
	err := s.db.QueryRowContext(ctx, `
		SELECT next_sequence, head_hash, checkpoint_id
		FROM loom_audit_chain_heads WHERE stream_id = $1
	`, strings.TrimSpace(streamID)).Scan(&nextSequence, &headHash, &checkpointID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", fmt.Errorf("%w: audit stream %q", core.ErrNotFound, streamID)
	}
	return nextSequence, headHash, checkpointID, err
}

var _ audit.Sink = (*AuditSink)(nil)
