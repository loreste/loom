// Package postgres provides durable backends for approval, idempotency,
// execution status, recovery coordination, policy, and audit.
// Fail-closed: connection/query errors surface to the runtime as denials where applicable.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // register pgx driver

	"github.com/loreste/loom/core"
)

//go:embed schema.sql
var schemaFS embed.FS

// PoolConfig tunes the SQL connection pool.
type PoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DefaultPool returns production-leaning pool settings.
func DefaultPool() PoolConfig {
	return PoolConfig{MaxOpenConns: 20, MaxIdleConns: 5, ConnMaxLifetime: time.Hour}
}

// Open connects with sane pool defaults. DSN is a postgres URL or key=value string.
func Open(dsn string) (*sql.DB, error) {
	return OpenPool(dsn, DefaultPool())
}

// OpenPool connects with custom pool settings.
func OpenPool(dsn string, pool PoolConfig) (*sql.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("%w: empty database url", core.ErrInvalidArgument)
	}
	if pool.MaxOpenConns <= 0 {
		pool.MaxOpenConns = 20
	}
	if pool.MaxIdleConns <= 0 {
		pool.MaxIdleConns = 5
	}
	if pool.ConnMaxLifetime <= 0 {
		pool.ConnMaxLifetime = time.Hour
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(pool.MaxOpenConns)
	db.SetMaxIdleConns(pool.MaxIdleConns)
	db.SetConnMaxLifetime(pool.ConnMaxLifetime)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	return db, nil
}

// Ready checks connectivity for /readyz.
func Ready(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("postgres: not configured")
	}
	return db.PingContext(ctx)
}

// Bundle groups durable stores sharing one pool.
type Bundle struct {
	DB              *sql.DB
	Approvals       *ApprovalStore
	Idempotency     *IdempotencyStore
	ExecutionStatus *ExecutionStore
	Audit           *AuditSink
	Policy          *PolicySource
	WebhookOutbox   *WebhookOutbox
}

// NewBundle opens, migrates, and returns stores.
func NewBundle(ctx context.Context, dsn string) (*Bundle, error) {
	return NewBundlePool(ctx, dsn, DefaultPool())
}

// NewBundlePool opens with custom pool settings.
func NewBundlePool(ctx context.Context, dsn string, pool PoolConfig) (*Bundle, error) {
	db, err := OpenPool(dsn, pool)
	if err != nil {
		return nil, err
	}
	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Bundle{
		DB:              db,
		Approvals:       NewApprovalStore(db),
		Idempotency:     NewIdempotencyStore(db),
		ExecutionStatus: NewExecutionStore(db),
		Audit:           NewAuditSink(db),
		Policy:          NewPolicySource(db),
		WebhookOutbox:   NewWebhookOutbox(db),
	}, nil
}

// Close closes the pool.
func (b *Bundle) Close() error {
	if b == nil || b.DB == nil {
		return nil
	}
	return b.DB.Close()
}
