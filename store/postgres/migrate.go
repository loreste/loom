package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5/pgconn"
)

// SchemaVersion is the embedded schema version (bump when schema.sql changes incompatibly).
const SchemaVersion = 2

// Migrate applies schema.sql and records version in loom_schema_meta.
// Fail-closed: if stored version > code version, refuse to start (prevents silent downgrade).
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("postgres: nil db")
	}
	b, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return err
	}

	// Read the stored version BEFORE applying schema.sql; the schema itself
	// must not stamp the version or the downgrade guard is dead.
	v, err := storedVersion(ctx, db)
	if err != nil {
		return err
	}
	if v > SchemaVersion {
		return fmt.Errorf("postgres: database schema version %d is newer than binary %d (refusing downgrade)", v, SchemaVersion)
	}

	if _, err := db.ExecContext(ctx, string(b)); err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO loom_schema_meta (key, value) VALUES ('version', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
	`, strconv.Itoa(SchemaVersion))
	return err
}

// storedVersion reads loom_schema_meta (0 on a fresh database).
// An unparseable version is an error, never silently treated as 0.
func storedVersion(ctx context.Context, db *sql.DB) (int, error) {
	var verStr string
	err := db.QueryRowContext(ctx, `SELECT value FROM loom_schema_meta WHERE key = 'version'`).Scan(&verStr)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" { // undefined_table: fresh DB
			return 0, nil
		}
		return 0, err
	}
	v, aerr := strconv.Atoi(verStr)
	if aerr != nil {
		return 0, fmt.Errorf("postgres: corrupt schema version %q: %w", verStr, aerr)
	}
	return v, nil
}

// CurrentVersion reads schema version from the database (0 if missing).
func CurrentVersion(ctx context.Context, db *sql.DB) (int, error) {
	var verStr string
	err := db.QueryRowContext(ctx, `SELECT value FROM loom_schema_meta WHERE key = 'version'`).Scan(&verStr)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(verStr)
}
