package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/idempotency"
)

// IdempotencyStore is a Postgres-backed idempotency.Store.
type IdempotencyStore struct {
	db *sql.DB
}

// NewIdempotencyStore wraps db.
func NewIdempotencyStore(db *sql.DB) *IdempotencyStore {
	return &IdempotencyStore{db: db}
}

// Get returns a completed, non-expired record.
func (s *IdempotencyStore) Get(ctx context.Context, key string) (*idempotency.Stored, bool, error) {
	if s == nil || s.db == nil || key == "" {
		return nil, false, nil
	}
	var (
		fp      string
		respRaw []byte
		inFlight bool
		exp     time.Time
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT fingerprint, response, in_flight, expires_at
		FROM loom_idempotency WHERE key = $1
	`, key).Scan(&fp, &respRaw, &inFlight, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if time.Now().After(exp) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM loom_idempotency WHERE key = $1`, key)
		return nil, false, nil
	}
	if inFlight || len(respRaw) == 0 {
		return nil, false, nil
	}
	var resp core.Response
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, false, fmt.Errorf("idempotency: corrupt response: %w", err)
	}
	return &idempotency.Stored{Fingerprint: fp, Response: resp, ExpiresAt: exp}, true, nil
}

// PutIfAbsent stores if free or same fingerprint.
func (s *IdempotencyStore) PutIfAbsent(ctx context.Context, key string, st *idempotency.Stored) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: nil store", core.ErrInvalidArgument)
	}
	raw, err := json.Marshal(st.Response)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var existingFP string
	err = tx.QueryRowContext(ctx, `
		SELECT fingerprint FROM loom_idempotency
		WHERE key = $1 AND expires_at > NOW() FOR UPDATE
	`, key).Scan(&existingFP)
	if err == nil {
		if existingFP != st.Fingerprint {
			return fmt.Errorf("%w: idempotency key conflict", core.ErrAlreadyExists)
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO loom_idempotency (key, fingerprint, response, in_flight, expires_at, updated_at)
		VALUES ($1, $2, $3, FALSE, $4, NOW())
		ON CONFLICT (key) DO UPDATE SET
			fingerprint = EXCLUDED.fingerprint,
			response = EXCLUDED.response,
			in_flight = FALSE,
			expires_at = EXCLUDED.expires_at,
			updated_at = NOW()
	`, key, st.Fingerprint, raw, st.ExpiresAt.UTC())
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Begin reserves an in-flight key.
func (s *IdempotencyStore) Begin(ctx context.Context, key, fingerprint string, ttl time.Duration) error {
	if s == nil || s.db == nil || key == "" {
		return fmt.Errorf("%w: key required", core.ErrInvalidArgument)
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	exp := time.Now().UTC().Add(ttl)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		fp       string
		respRaw  []byte
		inFlight bool
		expires  time.Time
	)
	err = tx.QueryRowContext(ctx, `
		SELECT fingerprint, response, in_flight, expires_at
		FROM loom_idempotency WHERE key = $1 FOR UPDATE
	`, key).Scan(&fp, &respRaw, &inFlight, &expires)

	if err == nil && time.Now().Before(expires) {
		if fp != fingerprint {
			return fmt.Errorf("%w: idempotency key conflict", core.ErrAlreadyExists)
		}
		if len(respRaw) > 0 && !inFlight {
			return fmt.Errorf("%w: already completed", core.ErrAlreadyExists)
		}
		if inFlight {
			return fmt.Errorf("%w: in flight", core.ErrAlreadyExists)
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO loom_idempotency (key, fingerprint, response, in_flight, expires_at, updated_at)
		VALUES ($1, $2, NULL, TRUE, $3, NOW())
		ON CONFLICT (key) DO UPDATE SET
			fingerprint = EXCLUDED.fingerprint,
			response = NULL,
			in_flight = TRUE,
			expires_at = EXCLUDED.expires_at,
			updated_at = NOW()
	`, key, fingerprint, exp)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Complete finalizes an in-flight key.
func (s *IdempotencyStore) Complete(ctx context.Context, key string, st *idempotency.Stored) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: nil store", core.ErrInvalidArgument)
	}
	raw, err := json.Marshal(st.Response)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE loom_idempotency
		SET response = $2, in_flight = FALSE, expires_at = $3, updated_at = NOW()
		WHERE key = $1 AND fingerprint = $4 AND in_flight = TRUE
	`, key, raw, st.ExpiresAt.UTC(), st.Fingerprint)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: key not in flight or fingerprint mismatch", core.ErrNotFound)
	}
	return nil
}

// Abort releases in-flight reservation.
func (s *IdempotencyStore) Abort(ctx context.Context, key string) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM loom_idempotency WHERE key = $1 AND in_flight = TRUE AND response IS NULL
	`, key)
	return err
}

var _ idempotency.Store = (*IdempotencyStore)(nil)
