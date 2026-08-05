package db

import (
	"context"
	"database/sql"
	"fmt"
)

// Tx is a guarded transaction. Same SQL rules as Executor; no raw *sql.Tx escape.
type Tx struct {
	ex *Executor
	tx *sql.Tx
}

// Begin starts a transaction on the scoped pool.
func (e *Executor) Begin(ctx context.Context) (*Tx, error) {
	if e == nil || e.pool == nil {
		return nil, fmt.Errorf("db: nil executor")
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

// Query runs a read inside the transaction.
func (t *Tx) Query(ctx context.Context, sqlText string, args ...any) (*ResultSet, error) {
	if t == nil || t.tx == nil {
		return nil, fmt.Errorf("db: nil tx")
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
