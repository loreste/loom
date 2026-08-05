// Package db provides secure, Loom-governed database connectivity.
//
// Design goals (adversarial):
//   - Application code does not hold raw DSNs after registration.
//   - Handlers never receive *sql.DB; they go through validated Executors
//     or governed operations (db.query / db.exec).
//   - Statements are classified and restricted (read vs write, single-statement,
//     no comment tricks, optional table allowlists).
//   - Connections are named pools scoped by boundary when configured.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

var tenantSettingPattern = regexp.MustCompile(`^app\.[A-Za-z_][A-Za-z0-9_]*$`)

func validateTenantSetting(setting string) error {
	if setting == "" {
		return nil
	}
	if !tenantSettingPattern.MatchString(setting) {
		return fmt.Errorf("db: tenant setting must be an app.* PostgreSQL setting")
	}
	return nil
}

// Options harden a named pool.
type Options struct {
	// ReadOnly rejects non-SELECT statements at the pool level.
	ReadOnly bool
	// MaxRows caps rows returned by Query (0 = default 1000).
	MaxRows int
	// MaxArgs caps bind parameters (0 = default 64).
	MaxArgs int
	// StatementTimeout applied via context if > 0.
	StatementTimeout time.Duration
	// AllowedTables if non-empty, statement must only reference these (simple heuristic).
	// Empty = no table filter (still subject to SQL class guards).
	AllowedTables []string
	// AllowedFunctions limits SQL function calls. Empty uses a small read-only
	// built-in set; extension and user-defined functions are denied.
	AllowedFunctions []string
	// AllowedBoundaries if non-empty, executor only works for these boundaries.
	AllowedBoundaries []core.BoundaryID
	// RequireTenantContext disallows direct pooled queries and requires
	// BeginTenant, which binds the verified boundary to a PostgreSQL transaction
	// with SET LOCAL semantics.
	RequireTenantContext bool
	// TenantSetting is the PostgreSQL custom setting used for RLS. Empty uses
	// the conventional app.tenant_id setting.
	TenantSetting string
	// DriverName for sql.Open (e.g. "pgx", "sqlite").
	DriverName string
	// Dialect overrides DetectDialect(DriverName). Zero = detect.
	Dialect Dialect
}

// Pool is a named connection pool with hard options.
type Pool struct {
	Name string
	opts Options
	db   *sql.DB
}

// Registry maps pool names → pools. Default deny: unknown name fails.
type Registry struct {
	mu    sync.RWMutex
	pools map[string]*Pool
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{pools: make(map[string]*Pool)}
}

// Open registers a pool. DSN is not retained after open (only the live pool).
func (r *Registry) Open(name, driver, dsn string, opts Options) error {
	if r == nil {
		return fmt.Errorf("%w: nil registry", core.ErrInvalidArgument)
	}
	if name == "" || driver == "" || dsn == "" {
		return fmt.Errorf("%w: name, driver, dsn required", core.ErrInvalidArgument)
	}
	if opts.MaxRows <= 0 {
		opts.MaxRows = 1000
	}
	if opts.MaxArgs <= 0 {
		opts.MaxArgs = 64
	}
	if opts.DriverName == "" {
		opts.DriverName = driver
	}
	if opts.TenantSetting == "" {
		opts.TenantSetting = "app.tenant_id"
	}
	if opts.RequireTenantContext {
		if err := validateTenantSetting(opts.TenantSetting); err != nil {
			return err
		}
	}
	opts.AllowedTables = append([]string(nil), opts.AllowedTables...)
	opts.AllowedFunctions = append([]string(nil), opts.AllowedFunctions...)
	if opts.Dialect == DialectUnknown {
		opts.Dialect = DetectDialect(opts.DriverName)
	}
	sqldb, err := sql.Open(driver, dsn)
	if err != nil {
		return err
	}
	sqldb.SetMaxOpenConns(10)
	sqldb.SetMaxIdleConns(5)
	sqldb.SetConnMaxLifetime(time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		return fmt.Errorf("db ping %q: %w", name, err)
	}
	// Zero DSN reference after open (cannot recover secret from Pool).
	dsn = ""
	_ = dsn

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.pools[name]; exists {
		_ = sqldb.Close()
		return fmt.Errorf("%w: pool %q", core.ErrAlreadyExists, name)
	}
	r.pools[name] = &Pool{Name: name, opts: opts, db: sqldb}
	return nil
}

// RegisterDB attaches an existing *sql.DB (tests). Caller retains close responsibility
// unless Registry.Close is used — prefer Open.
func (r *Registry) RegisterDB(name string, sqldb *sql.DB, opts Options) error {
	if r == nil || sqldb == nil || name == "" {
		return fmt.Errorf("%w: name and db required", core.ErrInvalidArgument)
	}
	if opts.MaxRows <= 0 {
		opts.MaxRows = 1000
	}
	if opts.MaxArgs <= 0 {
		opts.MaxArgs = 64
	}
	if opts.TenantSetting == "" {
		opts.TenantSetting = "app.tenant_id"
	}
	if opts.RequireTenantContext {
		if err := validateTenantSetting(opts.TenantSetting); err != nil {
			return err
		}
	}
	opts.AllowedTables = append([]string(nil), opts.AllowedTables...)
	opts.AllowedFunctions = append([]string(nil), opts.AllowedFunctions...)
	if opts.Dialect == DialectUnknown && opts.DriverName != "" {
		opts.Dialect = DetectDialect(opts.DriverName)
	}
	// sqlite memory registrations often omit DriverName — default sqlite when unknown.
	if opts.Dialect == DialectUnknown {
		opts.Dialect = DialectSQLite
		if opts.DriverName == "" {
			opts.DriverName = "sqlite"
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.pools[name]; exists {
		return fmt.Errorf("%w: pool %q", core.ErrAlreadyExists, name)
	}
	r.pools[name] = &Pool{Name: name, opts: opts, db: sqldb}
	return nil
}

// Get returns a pool or error.
func (r *Registry) Get(name string) (*Pool, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil registry", core.ErrInvalidArgument)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.pools[name]
	if !ok {
		return nil, fmt.Errorf("%w: pool %q", core.ErrNotFound, name)
	}
	return p, nil
}

// Names lists pool names.
func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.pools))
	for n := range r.pools {
		out = append(out, n)
	}
	return out
}

// Close closes all pools.
func (r *Registry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var first error
	for name, p := range r.pools {
		if p.db != nil {
			if err := p.db.Close(); err != nil && first == nil {
				first = err
			}
		}
		delete(r.pools, name)
	}
	return first
}

// Executor is a boundary/identity-scoped handle — not a raw *sql.DB.
type Executor struct {
	pool     *Pool
	identity core.Identity
	boundary core.BoundaryID
}

// ExecutorFor returns a scoped executor. Fails if boundary not allowed on pool.
func (r *Registry) ExecutorFor(name string, id core.Identity, boundary core.BoundaryID) (*Executor, error) {
	p, err := r.Get(name)
	if err != nil {
		return nil, err
	}
	if boundary == "" {
		return nil, fmt.Errorf("db: tenant boundary is required")
	}
	if len(p.opts.AllowedBoundaries) > 0 {
		ok := false
		for _, b := range p.opts.AllowedBoundaries {
			if b == boundary {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("db: pool %q not allowed in boundary %q", name, boundary)
		}
	}
	return &Executor{pool: p, identity: id, boundary: boundary}, nil
}

// Query runs a read statement after safety checks.
func (e *Executor) Query(ctx context.Context, sqlText string, args ...any) (*ResultSet, error) {
	if e == nil || e.pool == nil {
		return nil, fmt.Errorf("db: nil executor")
	}
	if e.pool.opts.RequireTenantContext {
		return nil, fmt.Errorf("db: tenant context required; use BeginTenant")
	}
	if err := validateArgs(len(args), e.pool.opts.MaxArgs); err != nil {
		return nil, err
	}
	class, tables, err := Classify(sqlText)
	if err != nil {
		return nil, err
	}
	if class != ClassRead {
		return nil, fmt.Errorf("db: query requires a read statement, got %s", class)
	}
	if err := checkTables(tables, e.pool.opts.AllowedTables); err != nil {
		return nil, err
	}
	if err := checkFunctions(sqlText, e.pool.opts.AllowedFunctions); err != nil {
		return nil, err
	}
	ctx, cancel := withTimeout(ctx, e.pool.opts.StatementTimeout)
	if cancel != nil {
		defer cancel()
	}
	sqlText, err = Rebind(e.pool.Dialect(), sqlText)
	if err != nil {
		return nil, err
	}
	rows, err := e.pool.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectRows(rows, e.pool.opts.MaxRows)
}

// QueryScoped runs a read in a tenant-bound transaction when the pool
// requires RLS; isolated pools use the normal guarded query path.
func (e *Executor) QueryScoped(ctx context.Context, sqlText string, args ...any) (*ResultSet, error) {
	if e == nil || e.pool == nil {
		return nil, fmt.Errorf("db: nil executor")
	}
	if !e.pool.opts.RequireTenantContext {
		return e.Query(ctx, sqlText, args...)
	}
	tx, err := e.BeginTenant(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return rows, nil
}

// Exec runs a write statement after safety checks.
func (e *Executor) Exec(ctx context.Context, sqlText string, args ...any) (ExecResult, error) {
	if e == nil || e.pool == nil {
		return ExecResult{}, fmt.Errorf("db: nil executor")
	}
	if e.pool.opts.RequireTenantContext {
		return ExecResult{}, fmt.Errorf("db: tenant context required; use BeginTenant")
	}
	if e.pool.opts.ReadOnly {
		return ExecResult{}, fmt.Errorf("db: pool %q is read-only", e.pool.Name)
	}
	if err := validateArgs(len(args), e.pool.opts.MaxArgs); err != nil {
		return ExecResult{}, err
	}
	class, tables, err := Classify(sqlText)
	if err != nil {
		return ExecResult{}, err
	}
	if class != ClassWrite {
		return ExecResult{}, fmt.Errorf("db: exec requires a write statement, got %s", class)
	}
	if err := checkTables(tables, e.pool.opts.AllowedTables); err != nil {
		return ExecResult{}, err
	}
	if err := checkFunctions(sqlText, e.pool.opts.AllowedFunctions); err != nil {
		return ExecResult{}, err
	}
	ctx, cancel := withTimeout(ctx, e.pool.opts.StatementTimeout)
	if cancel != nil {
		defer cancel()
	}
	sqlText, err = Rebind(e.pool.Dialect(), sqlText)
	if err != nil {
		return ExecResult{}, err
	}
	res, err := e.pool.db.ExecContext(ctx, sqlText, args...)
	if err != nil {
		return ExecResult{}, err
	}
	ra, _ := res.RowsAffected()
	return ExecResult{RowsAffected: ra}, nil
}

// ResultSet is a safe row payload for handlers / operations.
type ResultSet struct {
	Columns []string         `json:"columns"`
	Rows    []map[string]any `json:"rows"`
	// Truncated if MaxRows hit.
	Truncated bool `json:"truncated,omitempty"`
}

// ExecResult is write outcome.
type ExecResult struct {
	RowsAffected int64 `json:"rows_affected"`
}

func validateArgs(n, max int) error {
	if n > max {
		return fmt.Errorf("db: too many args (%d > %d)", n, max)
	}
	return nil
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, nil
	}
	return context.WithTimeout(ctx, d)
}

func checkTables(used, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	// Fail closed: an allowlist with zero extracted tables (e.g. SELECT pg_ls_dir(...))
	// must not pass — table-less statements can still be dangerous.
	if len(used) == 0 {
		return fmt.Errorf("db: statement references no allowlisted tables")
	}
	set := make(map[string]struct{}, len(allowed))
	for _, t := range allowed {
		set[normalizeIdent(t)] = struct{}{}
	}
	for _, u := range used {
		if _, ok := set[normalizeIdent(u)]; !ok {
			return fmt.Errorf("db: table %q not in allowlist", u)
		}
	}
	return nil
}

func collectRows(rows *sql.Rows, max int) (*ResultSet, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := &ResultSet{Columns: cols, Rows: make([]map[string]any, 0, 16)}
	raw := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	for rows.Next() {
		if len(out.Rows) >= max {
			out.Truncated = true
			break
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			row[c] = normalizeValue(raw[i])
		}
		out.Rows = append(out.Rows, row)
	}
	return out, rows.Err()
}

func normalizeValue(v any) any {
	switch t := v.(type) {
	case []byte:
		return string(t)
	case time.Time:
		return t.UTC().Format(time.RFC3339Nano)
	default:
		return t
	}
}
