package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/loreste/loom/approval"
	"github.com/loreste/loom/core"
)

// ApprovalStore is a Postgres-backed approval.Store.
type ApprovalStore struct {
	db *sql.DB
}

// NewApprovalStore wraps db.
func NewApprovalStore(db *sql.DB) *ApprovalStore {
	return &ApprovalStore{db: db}
}

func hashTok(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Issue implements approval.Issuer. Tokens stored hashed only.
func (s *ApprovalStore) Issue(token string, principal core.PrincipalID, op string, boundary core.BoundaryID, maxRisk core.RiskLevel, ttl time.Duration) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: nil store", core.ErrInvalidArgument)
	}
	if token == "" || principal == "" || op == "" {
		return fmt.Errorf("%w: token, principal, operation required", core.ErrInvalidArgument)
	}
	if ttl <= 0 {
		return fmt.Errorf("%w: ttl must be positive", core.ErrInvalidArgument)
	}
	h := hashTok(token)
	exp := time.Now().UTC().Add(ttl)
	_, err := s.db.Exec(`
		INSERT INTO loom_approvals (token_hash, principal, operation, boundary, max_risk, expires_at, consumed, single_use)
		VALUES ($1, $2, $3, $4, $5, $6, FALSE, TRUE)
		ON CONFLICT (token_hash) DO UPDATE SET
			principal = EXCLUDED.principal,
			operation = EXCLUDED.operation,
			boundary = EXCLUDED.boundary,
			max_risk = EXCLUDED.max_risk,
			expires_at = EXCLUDED.expires_at,
			consumed = FALSE,
			single_use = TRUE
	`, h, string(principal), op, string(boundary), int(maxRisk), exp)
	return err
}

// Evaluate implements approval.Engine. It checks the token WITHOUT consuming it;
// the runtime calls Consume only after the handler succeeded. The stored boundary
// must match the request boundary exactly (fail closed).
func (s *ApprovalStore) Evaluate(ctx context.Context, id core.Identity, op *core.Operation, risk core.RiskLevel, boundary core.BoundaryID, token string) approval.Decision {
	if op == nil {
		return approval.Decision{Required: true, Approved: false, Message: "nil operation"}
	}
	if !approval.Required(op, risk) {
		return approval.Decision{Required: false, Approved: true, Message: "approval not required"}
	}
	if token == "" {
		return approval.Decision{Required: true, Approved: false, Message: "approval token required"}
	}
	if s == nil || s.db == nil {
		return approval.Decision{Required: true, Approved: false, Message: "approval store not configured"}
	}

	h := hashTok(token)
	var (
		principal string
		operation string
		recBoundary string
		maxRisk   int
		expires   time.Time
		consumed  bool
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT principal, operation, boundary, max_risk, expires_at, consumed
		FROM loom_approvals WHERE token_hash = $1
	`, h).Scan(&principal, &operation, &recBoundary, &maxRisk, &expires, &consumed)
	if err == sql.ErrNoRows {
		return approval.Decision{Required: true, Approved: false, Message: "unknown approval token"}
	}
	if err != nil {
		return approval.Decision{Required: true, Approved: false, Message: "approval store error"}
	}
	if consumed {
		return approval.Decision{Required: true, Approved: false, Message: "approval token already consumed"}
	}
	if time.Now().After(expires) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM loom_approvals WHERE token_hash = $1`, h)
		return approval.Decision{Required: true, Approved: false, Message: "approval token expired"}
	}
	if core.PrincipalID(principal) != id.ID {
		return approval.Decision{Required: true, Approved: false, Message: "approval principal mismatch"}
	}
	if operation != "*" && operation != op.Name {
		return approval.Decision{Required: true, Approved: false, Message: "approval operation mismatch"}
	}
	if core.BoundaryID(recBoundary) != boundary {
		return approval.Decision{Required: true, Approved: false, Message: "approval boundary mismatch"}
	}
	if risk > core.RiskLevel(maxRisk) {
		return approval.Decision{Required: true, Approved: false, Message: "risk exceeds approved maximum"}
	}
	return approval.Decision{Required: true, Approved: true, Message: "approval token accepted"}
}

// Consume implements approval.Engine. Burns a single-use token transactionally
// (SELECT ... FOR UPDATE + conditional UPDATE) after successful execution.
// Any error means the token was NOT consumed (fail closed).
func (s *ApprovalStore) Consume(ctx context.Context, id core.Identity, op *core.Operation, boundary core.BoundaryID, token string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: nil store", core.ErrInvalidArgument)
	}
	if token == "" || op == nil {
		return fmt.Errorf("%w: token and operation required", core.ErrInvalidArgument)
	}

	h := hashTok(token)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("approval: store unavailable: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		principal string
		operation string
		recBoundary string
		expires   time.Time
		singleUse bool
	)
	err = tx.QueryRowContext(ctx, `
		SELECT principal, operation, boundary, expires_at, single_use
		FROM loom_approvals WHERE token_hash = $1 AND consumed = FALSE FOR UPDATE
	`, h).Scan(&principal, &operation, &recBoundary, &expires, &singleUse)
	if err == sql.ErrNoRows {
		return fmt.Errorf("approval: unknown or already consumed token")
	}
	if err != nil {
		return fmt.Errorf("approval: store error: %w", err)
	}
	if time.Now().After(expires) {
		return fmt.Errorf("approval: token expired")
	}
	if core.PrincipalID(principal) != id.ID {
		return fmt.Errorf("approval: principal mismatch")
	}
	if operation != "*" && operation != op.Name {
		return fmt.Errorf("approval: operation mismatch")
	}
	if core.BoundaryID(recBoundary) != boundary {
		return fmt.Errorf("approval: boundary mismatch")
	}
	if singleUse {
		res, err := tx.ExecContext(ctx, `
			UPDATE loom_approvals SET consumed = TRUE WHERE token_hash = $1 AND consumed = FALSE
		`, h)
		if err != nil {
			return fmt.Errorf("approval: consume failed: %w", err)
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return fmt.Errorf("approval: token already consumed")
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("approval: commit failed: %w", err)
	}
	return nil
}

// PurgeExpired removes expired rows (optional maintenance).
func (s *ApprovalStore) PurgeExpired(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM loom_approvals WHERE expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

var _ approval.Store = (*ApprovalStore)(nil)
