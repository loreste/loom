package db

import (
	"context"
	"database/sql"
	"fmt"
)

// Tx is a guarded transaction. Same SQL rules as Executor; no raw *sql.Tx escape.
type Tx struct {
	ex          *Executor
	tx          *sql.Tx
	tenantBound bool
}

// Begin starts a transaction on the scoped pool.
func (e *Executor) Begin(ctx context.Context) (*Tx, error) {
	if e == nil || e.pool == nil {
		return nil, fmt.Errorf("db: nil executor")
	}
	if e.pool.opts.RequireTenantContext {
		return nil, fmt.Errorf("db: tenant context required; use BeginTenant")
	}
	if e.pool.opts.ReadOnly {
		return nil, fmt.Errorf("db: pool %q is read-only (no transactions for writes)", e.pool.Name)
	}
	tx, err := e.pool.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: false})
	if err != nil {
		return nil, err
	}
	return &Tx{ex: e, tx: tx}, nil
}

// BeginScoped chooses the normal transaction for isolated pools and the RLS
// transaction for pools that require tenant context.
func (e *Executor) BeginScoped(ctx context.Context) (*Tx, error) {
	if e == nil || e.pool == nil {
		return nil, fmt.Errorf("db: nil executor")
	}
	if e.pool.opts.RequireTenantContext {
		return e.BeginTenant(ctx)
	}
	return e.Begin(ctx)
}

// BeginTenant starts a transaction and binds the verified executor boundary to
// a PostgreSQL transaction-local setting. Governed SQL cannot call set_config
// and change it later.
func (e *Executor) BeginTenant(ctx context.Context) (*Tx, error) {
	if e == nil || e.pool == nil {
		return nil, fmt.Errorf("db: nil executor")
	}
	if e.pool.Dialect() != DialectPostgres {
		return nil, fmt.Errorf("db: tenant RLS transactions require PostgreSQL")
	}
	if e.boundary == "" {
		return nil, fmt.Errorf("db: tenant boundary is required")
	}
	tx, err := e.pool.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: e.pool.opts.ReadOnly})
	if err != nil {
		return nil, err
	}
	setting := e.pool.opts.TenantSetting
	if setting == "" {
		setting = "app.tenant_id"
	}
	query, err := Rebind(e.pool.Dialect(), "SELECT set_config(?, ?, true)")
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, query, setting, string(e.boundary)); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("db: bind tenant context: %w", err)
	}
	return &Tx{ex: e, tx: tx, tenantBound: true}, nil
}

// Query runs a read inside the transaction.
func (t *Tx) Query(ctx context.Context, sqlText string, args ...any) (*ResultSet, error) {
	if t == nil || t.tx == nil {
		return nil, fmt.Errorf("db: nil tx")
	}
	if t.ex.pool.opts.RequireTenantContext && !t.tenantBound {
		return nil, fmt.Errorf("db: tenant context was not bound")
	}
	if err := validateArgs(len(args), t.ex.pool.opts.MaxArgs); err != nil {
		return nil, err
	}
	class, tables, err := Classify(sqlText)
	if err != nil {
		return nil, err
	}
	if class != ClassRead {
		return nil, fmt.Errorf("db: query requires a read statement, got %s", class)
	}
	if err := checkTables(tables, t.ex.pool.opts.AllowedTables); err != nil {
		return nil, err
	}
	if err := checkFunctions(sqlText, t.ex.pool.opts.AllowedFunctions); err != nil {
		return nil, err
	}
	ctx, cancel := withTimeout(ctx, t.ex.pool.opts.StatementTimeout)
	if cancel != nil {
		defer cancel()
	}
	sqlText, err = Rebind(t.ex.pool.Dialect(), sqlText)
	if err != nil {
		return nil, err
	}
	rows, err := t.tx.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectRows(rows, t.ex.pool.opts.MaxRows)
}

// Exec runs a write inside the transaction.
func (t *Tx) Exec(ctx context.Context, sqlText string, args ...any) (ExecResult, error) {
	if t == nil || t.tx == nil {
		return ExecResult{}, fmt.Errorf("db: nil tx")
	}
	if t.ex.pool.opts.RequireTenantContext && !t.tenantBound {
		return ExecResult{}, fmt.Errorf("db: tenant context was not bound")
	}
	if err := validateArgs(len(args), t.ex.pool.opts.MaxArgs); err != nil {
		return ExecResult{}, err
	}
	class, tables, err := Classify(sqlText)
	if err != nil {
		return ExecResult{}, err
	}
	if class != ClassWrite {
		return ExecResult{}, fmt.Errorf("db: exec requires a write statement, got %s", class)
	}
	if err := checkTables(tables, t.ex.pool.opts.AllowedTables); err != nil {
		return ExecResult{}, err
	}
	if err := checkFunctions(sqlText, t.ex.pool.opts.AllowedFunctions); err != nil {
		return ExecResult{}, err
	}
	ctx, cancel := withTimeout(ctx, t.ex.pool.opts.StatementTimeout)
	if cancel != nil {
		defer cancel()
	}
	sqlText, err = Rebind(t.ex.pool.Dialect(), sqlText)
	if err != nil {
		return ExecResult{}, err
	}
	res, err := t.tx.ExecContext(ctx, sqlText, args...)
	if err != nil {
		return ExecResult{}, err
	}
	ra, _ := res.RowsAffected()
	return ExecResult{RowsAffected: ra}, nil
}

// Commit finalizes the transaction.
func (t *Tx) Commit() error {
	if t == nil || t.tx == nil {
		return fmt.Errorf("db: nil tx")
	}
	err := t.tx.Commit()
	t.tx = nil
	return err
}

// Rollback aborts. Safe to call after Commit (returns error from driver).
func (t *Tx) Rollback() error {
	if t == nil || t.tx == nil {
		return nil
	}
	err := t.tx.Rollback()
	t.tx = nil
	return err
}
