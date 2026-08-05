package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// InsertOpts configures a dialect-aware insert that returns columns.
type InsertOpts struct {
	// Table must be a simple identifier (optionally schema.table). Validated strictly.
	Table string
	// Columns are insert column names (validated identifiers).
	Columns []string
	// Values bind args, one per column.
	Values []any
	// Returning columns to fetch (default ["id"] if empty).
	Returning []string
}

// InsertReturning inserts a row and returns selected columns.
//
// Postgres: INSERT … RETURNING …
// SQLite: INSERT … ; then SELECT … WHERE rowid = last_insert_rowid()
//
// Table/column names are identifier-validated (no user-controlled free SQL).
func (e *Executor) InsertReturning(ctx context.Context, opts InsertOpts) (map[string]any, error) {
	if e == nil {
		return nil, fmt.Errorf("db: nil executor")
	}
	if e.pool != nil && e.pool.Dialect() == DialectSQLite {
		// last_insert_rowid() is connection-local: pin INSERT + SELECT to one
		// dedicated connection so they cannot land on different pooled conns.
		conn, err := e.pool.db.Conn(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = conn.Close() }()
		q := func(ctx context.Context, sqlText string, args ...any) (*ResultSet, error) {
			return guardedQuery(ctx, e.pool, conn, sqlText, args...)
		}
		x := func(ctx context.Context, sqlText string, args ...any) (ExecResult, error) {
			return guardedExec(ctx, e.pool, conn, sqlText, args...)
		}
		return insertReturning(ctx, e.pool, q, x, opts)
	}
	return insertReturning(ctx, e.pool, e.Query, e.Exec, opts)
}

// InsertReturning on a transaction.
func (t *Tx) InsertReturning(ctx context.Context, opts InsertOpts) (map[string]any, error) {
	if t == nil || t.ex == nil {
		return nil, fmt.Errorf("db: nil tx")
	}
	return insertReturning(ctx, t.ex.pool, t.Query, t.Exec, opts)
}

type (
	queryFn func(ctx context.Context, sqlText string, args ...any) (*ResultSet, error)
	execFn  func(ctx context.Context, sqlText string, args ...any) (ExecResult, error)
)

func insertReturning(ctx context.Context, pool *Pool, q queryFn, x execFn, opts InsertOpts) (map[string]any, error) {
	if pool == nil {
		return nil, fmt.Errorf("db: nil pool")
	}
	table, err := quoteIdent(opts.Table)
	if err != nil {
		return nil, err
	}
	if len(opts.Columns) == 0 || len(opts.Columns) != len(opts.Values) {
		return nil, fmt.Errorf("db: columns/values length mismatch")
	}
	cols := make([]string, len(opts.Columns))
	for i, c := range opts.Columns {
		qc, err := quoteIdent(c)
		if err != nil {
			return nil, err
		}
		cols[i] = qc
	}
	ret := opts.Returning
	if len(ret) == 0 {
		ret = []string{"id"}
	}
	retCols := make([]string, len(ret))
	for i, c := range ret {
		qc, err := quoteIdent(c)
		if err != nil {
			return nil, err
		}
		retCols[i] = qc
	}
	// table allowlist still enforced via Classify on built SQL
	placeholders := make([]string, len(opts.Values))
	for i := range placeholders {
		placeholders[i] = "?"
	}
	insertSQL := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		table,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
	)

	switch pool.Dialect() {
	case DialectPostgres:
		sqlText := insertSQL + " RETURNING " + strings.Join(retCols, ", ")
		// RETURNING makes this a write that returns rows — run as Query after classify.
		// Our Classify treats INSERT as write, so Query() rejects it.
		// Use special path: Exec is wrong for RETURNING. Use queryInsertReturning.
		return queryWriteReturning(ctx, pool, q, sqlText, opts.Values)
	case DialectSQLite:
		if _, err := x(ctx, insertSQL, opts.Values...); err != nil {
			return nil, err
		}
		// last_insert_rowid() is sqlite-specific and read-class
		sel := fmt.Sprintf(
			"SELECT %s FROM %s WHERE rowid = last_insert_rowid()",
			strings.Join(retCols, ", "),
			table,
		)
		rs, err := q(ctx, sel)
		if err != nil {
			return nil, err
		}
		if len(rs.Rows) == 0 {
			return nil, fmt.Errorf("db: insert returned no row")
		}
		return rs.Rows[0], nil
	default:
		return nil, fmt.Errorf("db: unsupported dialect for InsertReturning")
	}
}

// sqlRunner is satisfied by *sql.DB, *sql.Conn and *sql.Tx.
type sqlRunner interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// guardedExec applies the same write guards as Executor.Exec against an explicit runner.
func guardedExec(ctx context.Context, pool *Pool, r sqlRunner, sqlText string, args ...any) (ExecResult, error) {
	if pool.opts.ReadOnly {
		return ExecResult{}, fmt.Errorf("db: pool %q is read-only", pool.Name)
	}
	if err := validateArgs(len(args), pool.opts.MaxArgs); err != nil {
		return ExecResult{}, err
	}
	class, tables, err := Classify(sqlText)
	if err != nil {
		return ExecResult{}, err
	}
	if class != ClassWrite {
		return ExecResult{}, fmt.Errorf("db: exec requires a write statement, got %s", class)
	}
	if err := checkTables(tables, pool.opts.AllowedTables); err != nil {
		return ExecResult{}, err
	}
	ctx, cancel := withTimeout(ctx, pool.opts.StatementTimeout)
	if cancel != nil {
		defer cancel()
	}
	sqlText, err = Rebind(pool.Dialect(), sqlText)
	if err != nil {
		return ExecResult{}, err
	}
	res, err := r.ExecContext(ctx, sqlText, args...)
	if err != nil {
		return ExecResult{}, err
	}
	ra, _ := res.RowsAffected()
	return ExecResult{RowsAffected: ra}, nil
}

// guardedQuery applies the same read guards as Executor.Query against an explicit runner.
func guardedQuery(ctx context.Context, pool *Pool, r sqlRunner, sqlText string, args ...any) (*ResultSet, error) {
	if err := validateArgs(len(args), pool.opts.MaxArgs); err != nil {
		return nil, err
	}
	class, tables, err := Classify(sqlText)
	if err != nil {
		return nil, err
	}
	if class != ClassRead {
		return nil, fmt.Errorf("db: query requires a read statement, got %s", class)
	}
	if err := checkTables(tables, pool.opts.AllowedTables); err != nil {
		return nil, err
	}
	ctx, cancel := withTimeout(ctx, pool.opts.StatementTimeout)
	if cancel != nil {
		defer cancel()
	}
	sqlText, err = Rebind(pool.Dialect(), sqlText)
	if err != nil {
		return nil, err
	}
	rows, err := r.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectRows(rows, pool.opts.MaxRows)
}

// queryWriteReturning runs INSERT…RETURNING via the underlying pool with write classification.
func queryWriteReturning(ctx context.Context, pool *Pool, _ queryFn, sqlText string, args []any) (map[string]any, error) {
	if err := validateArgs(len(args), pool.opts.MaxArgs); err != nil {
		return nil, err
	}
	class, tables, err := Classify(sqlText)
	if err != nil {
		// INSERT … RETURNING may fail classify if we only allow pure INSERT —
		// strip RETURNING for classification then execute full SQL.
		base := sqlText
		if i := strings.Index(strings.ToUpper(sqlText), " RETURNING "); i > 0 {
			base = sqlText[:i]
		}
		class, tables, err = Classify(base)
		if err != nil {
			return nil, err
		}
	}
	if class != ClassWrite {
		return nil, fmt.Errorf("db: insert returning requires write statement, got %s", class)
	}
	if pool.opts.ReadOnly {
		return nil, fmt.Errorf("db: pool %q is read-only", pool.Name)
	}
	if err := checkTables(tables, pool.opts.AllowedTables); err != nil {
		return nil, err
	}
	sqlText, err = Rebind(pool.Dialect(), sqlText)
	if err != nil {
		return nil, err
	}
	ctx, cancel := withTimeout(ctx, pool.opts.StatementTimeout)
	if cancel != nil {
		defer cancel()
	}
	rows, err := pool.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rs, err := collectRows(rows, 1)
	if err != nil {
		return nil, err
	}
	if len(rs.Rows) == 0 {
		return nil, fmt.Errorf("db: insert returning no row")
	}
	return rs.Rows[0], nil
}

// quoteIdent allows schema.table or table, letters/digits/_ only.
func quoteIdent(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("db: empty identifier")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return "", fmt.Errorf("db: invalid identifier %q", s)
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || !isSafeIdent(p) {
			return "", fmt.Errorf("db: invalid identifier %q", s)
		}
		out = append(out, p)
	}
	return strings.Join(out, "."), nil
}

func isSafeIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}
