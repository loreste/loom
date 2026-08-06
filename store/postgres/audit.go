package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/core"
)

// AuditSink persists audit events to Postgres.
// Write failures return error; post-side-effect allow failures become an
// executed_unconfirmed outcome and must be monitored.
// Deny paths remain denied; operators should monitor all write failures.
type AuditSink struct {
	db *sql.DB
}

// Durable reports that audit records are persisted in PostgreSQL.
func (s *AuditSink) Durable() bool { return s != nil && s.db != nil }

// NewAuditSink wraps db.
func NewAuditSink(db *sql.DB) *AuditSink {
	return &AuditSink{db: db}
}

// Write implements audit.Sink.
func (s *AuditSink) Write(ctx context.Context, ev audit.Event) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: audit sink not configured", core.ErrInvalidArgument)
	}
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
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO loom_audit (
			id, schema_version, event_type, ts, execution_id, trace_id,
			protocol_version, decision, outcome, reason, step, message,
			principal, delegator, boundary, boundary_type, boundary_parent_type,
			boundary_parent_id, tenant_id, operation, operation_version, resource,
			resource_type, resource_id, effects, risk, input, input_digest,
			output_digest, output_field_count, requested_field_count, metadata,
			duration_ms, auth_method, idempotency_key_digest, idempotency_state,
			approval_state, quota_state, reliability_warning, adapter, prior_audit_id,
			execution_state, execution_revision, recovery_queued, reconciliation_note
		) VALUES (
			$1,$2,$3,$4,$5,$6,
			$7,$8,$9,$10,$11,$12,
			$13,$14,$15,$16,$17,
			$18,$19,$20,$21,$22,
			$23,$24,$25,$26,$27,$28,
			$29,$30,$31,$32,$33,$34,
			$35,$36,$37,$38,$39,$40,$41,
			$42,$43,$44,$45
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
	)
	return err
}

var _ audit.Sink = (*AuditSink)(nil)
