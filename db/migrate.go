package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"
)

// Migration is a one-way schema step applied at process startup on *sql.DB
// (before or outside Loom SQL guards — DDL is intentionally blocked in app SQL).
type Migration struct {
	// Version must be monotonically increasing positive integers.
	Version int
	// Name is for logs only.
	Name string
	// Up is the SQL to apply (may contain multiple statements separated by ;).
	// Startup migrations are the one place multi-statement is allowed.
	Up string
}

// Migrator applies versioned migrations on a raw *sql.DB.
type Migrator struct {
	DB      *sql.DB
	Dialect Dialect
	// Table defaults to loom_schema_migrations.
	Table string
}

// NewMigrator constructs a migrator. Dialect zero → sqlite.
func NewMigrator(sqldb *sql.DB, dialect Dialect) *Migrator {
	if dialect == DialectUnknown {
		dialect = DialectSQLite
	}
	return &Migrator{DB: sqldb, Dialect: dialect, Table: "loom_schema_migrations"}
}

// Apply runs pending migrations in version order inside individual transactions when possible.
func (m *Migrator) Apply(ctx context.Context, migrations []Migration) error {
	if m == nil || m.DB == nil {
		return fmt.Errorf("db: nil migrator")
	}
	if m.Table == "" {
		m.Table = "loom_schema_migrations"
	}
	if !isSafeIdent(m.Table) {
		return fmt.Errorf("db: invalid migration table %q", m.Table)
	}
	if err := m.ensureTable(ctx); err != nil {
		return err
	}
	applied, err := m.applied(ctx)
	if err != nil {
		return err
	}
	sorted := append([]Migration(nil), migrations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Version < sorted[j].Version })
	for _, mig := range sorted {
		if mig.Version <= 0 {
			return fmt.Errorf("db: migration version must be > 0 (%q)", mig.Name)
		}
		if applied[mig.Version] {
			continue
		}
		if err := m.applyOne(ctx, mig); err != nil {
			return fmt.Errorf("db: migration %d %s: %w", mig.Version, mig.Name, err)
		}
	}
	return nil
}

func (m *Migrator) ensureTable(ctx context.Context) error {
	// dialect-specific PK types
	var ddl string
	switch m.Dialect {
	case DialectPostgres:
		ddl = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			version BIGINT PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`, m.Table)
	default:
		ddl = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			applied_at TEXT NOT NULL
		)`, m.Table)
	}
	_, err := m.DB.ExecContext(ctx, ddl)
	return err
}

func (m *Migrator) applied(ctx context.Context) (map[int]bool, error) {
	rows, err := m.DB.QueryContext(ctx, fmt.Sprintf(`SELECT version FROM %s`, m.Table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func (m *Migrator) applyOne(ctx context.Context, mig Migration) error {
	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, mig.Up); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var insert string
	switch m.Dialect {
	case DialectPostgres:
		insert = fmt.Sprintf(`INSERT INTO %s (version, name, applied_at) VALUES ($1, $2, NOW())`, m.Table)
		_, err = tx.ExecContext(ctx, insert, mig.Version, mig.Name)
	default:
		insert = fmt.Sprintf(`INSERT INTO %s (version, name, applied_at) VALUES (?, ?, ?)`, m.Table)
		_, err = tx.ExecContext(ctx, insert, mig.Version, mig.Name, now)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// CurrentVersion returns the highest applied migration version (0 if none).
func (m *Migrator) CurrentVersion(ctx context.Context) (int, error) {
	if m.Table == "" {
		m.Table = "loom_schema_migrations"
	}
	if !isSafeIdent(m.Table) {
		return 0, fmt.Errorf("db: invalid migration table %q", m.Table)
	}
	if err := m.ensureTable(ctx); err != nil {
		return 0, err
	}
	var v sql.NullInt64
	err := m.DB.QueryRowContext(ctx, fmt.Sprintf(`SELECT MAX(version) FROM %s`, m.Table)).Scan(&v)
	if err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}
