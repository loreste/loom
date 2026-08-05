package db_test

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/db"
)

func TestMigratorApplyIdempotent(t *testing.T) {
	sqldb, err := sql.Open("sqlite", "file:migtest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })

	m := db.NewMigrator(sqldb, db.DialectSQLite)
	migs := []db.Migration{
		{Version: 1, Name: "notes", Up: `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`},
		{Version: 2, Name: "notes_idx", Up: `CREATE INDEX idx_notes_body ON notes(body)`},
	}
	if err := m.Apply(context.Background(), migs); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(context.Background(), migs); err != nil {
		t.Fatal(err) // second apply no-op
	}
	v, err := m.CurrentVersion(context.Background())
	if err != nil || v != 2 {
		t.Fatalf("version %d %v", v, err)
	}
	var n int
	if err := sqldb.QueryRow(`SELECT COUNT(*) FROM notes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("notes table should exist and be empty, got %d rows", n)
	}
}

func TestMigratorRejectsUnsafeTable(t *testing.T) {
	sqldb, err := sql.Open("sqlite", "file:migbad?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })

	bad := []string{
		`migrations; DROP TABLE users`,
		`bad name`,
		`"quoted"`,
		`public.migrations`,
		`1leading_digit`,
	}
	for _, tbl := range bad {
		m := db.NewMigrator(sqldb, db.DialectSQLite)
		m.Table = tbl
		if err := m.Apply(context.Background(), nil); err == nil {
			t.Fatalf("Apply accepted unsafe table %q", tbl)
		}
		if _, err := m.CurrentVersion(context.Background()); err == nil {
			t.Fatalf("CurrentVersion accepted unsafe table %q", tbl)
		}
	}

	// a safe custom table still works
	m := db.NewMigrator(sqldb, db.DialectSQLite)
	m.Table = "custom_migrations"
	migs := []db.Migration{
		{Version: 1, Name: "t", Up: `CREATE TABLE mig_t (id INTEGER PRIMARY KEY)`},
	}
	if err := m.Apply(context.Background(), migs); err != nil {
		t.Fatal(err)
	}
	if v, err := m.CurrentVersion(context.Background()); err != nil || v != 1 {
		t.Fatalf("version %d %v", v, err)
	}
}
