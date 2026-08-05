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
// Write failures return error; runtime still returns the enforcement decision
// (audit must not grant access, but operators should monitor failures).
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
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO loom_audit (
			id, ts, trace_id, decision, reason, step, message,
			principal, delegator, boundary, operation, resource, risk,
			input, metadata, duration_ms, auth_method
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,
			$8,$9,$10,$11,$12,$13,
			$14,$15,$16,$17
		)
		ON CONFLICT (id) DO NOTHING
	`,
		ev.ID, ev.Timestamp.UTC(), ev.TraceID, ev.Decision, ev.Reason, ev.Step, ev.Message,
		ev.Principal, ev.Delegator, ev.Boundary, ev.Operation, ev.Resource, ev.Risk,
		inRaw, mdRaw, ev.DurationMS, ev.AuthMethod,
	)
	return err
}

var _ audit.Sink = (*AuditSink)(nil)
