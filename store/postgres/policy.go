package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/policy"
)

// PolicySource is a Postgres-backed distributed policy Source.
type PolicySource struct {
	DB *sql.DB
	// ID namespace (default "default").
	ID string
}

// NewPolicySource wraps db.
func NewPolicySource(db *sql.DB) *PolicySource {
	return &PolicySource{DB: db, ID: "default"}
}

// Load implements policy.Source.
func (s *PolicySource) Load(ctx context.Context) (*policy.Document, error) {
	if s == nil || s.DB == nil {
		return nil, fmt.Errorf("%w: nil policy source", core.ErrInvalidArgument)
	}
	id := s.ID
	if id == "" {
		id = "default"
	}
	var (
		version int64
		raw     []byte
		updated time.Time
	)
	err := s.DB.QueryRowContext(ctx, `
		SELECT version, document, updated_at FROM loom_policy WHERE id = $1
	`, id).Scan(&version, &raw, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	doc, err := policy.ParseDocument(raw)
	if err != nil {
		return nil, err
	}
	doc.Version = version
	doc.UpdatedAt = updated
	doc.ID = id
	return doc, nil
}

// Publish implements policy.Source. Rejects non-increasing versions.
func (s *PolicySource) Publish(ctx context.Context, doc *policy.Document) error {
	if s == nil || s.DB == nil {
		return fmt.Errorf("%w: nil policy source", core.ErrInvalidArgument)
	}
	if doc == nil || doc.Version <= 0 {
		return fmt.Errorf("%w: version must be > 0", core.ErrInvalidArgument)
	}
	id := doc.ID
	if id == "" {
		id = s.ID
	}
	if id == "" {
		id = "default"
	}
	doc.ID = id
	doc.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var cur sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT version FROM loom_policy WHERE id = $1 FOR UPDATE`, id).Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if cur.Valid && doc.Version <= cur.Int64 {
		return fmt.Errorf("%w: policy version %d <= current %d", core.ErrAlreadyExists, doc.Version, cur.Int64)
	}
	// The WHERE clause makes the upsert conditional at the storage layer too:
	// two first-time concurrent publishes both see ErrNoRows above, and without
	// it the later commit would win regardless of version.
	res, err := tx.ExecContext(ctx, `
		INSERT INTO loom_policy (id, version, document, updated_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET
			version = EXCLUDED.version,
			document = EXCLUDED.document,
			updated_at = EXCLUDED.updated_at
		WHERE loom_policy.version < EXCLUDED.version
	`, id, doc.Version, raw, doc.UpdatedAt)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: policy version %d is stale (concurrent publish won)", core.ErrAlreadyExists, doc.Version)
	}
	return tx.Commit()
}

var _ policy.Source = (*PolicySource)(nil)
