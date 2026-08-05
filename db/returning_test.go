package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
)

func TestInsertReturningSQLite(t *testing.T) {
	sqldb, err := sql.Open("sqlite", "file:ret?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	_, _ = sqldb.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`)

	reg := db.NewRegistry()
	_ = reg.RegisterDB("main", sqldb, db.Options{
		DriverName:    "sqlite",
		Dialect:       db.DialectSQLite,
		AllowedTables: []string{"items"},
	})
	ex, err := reg.ExecutorFor("main", core.Identity{ID: "u"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	row, err := ex.InsertReturning(context.Background(), db.InsertOpts{
		Table:     "items",
		Columns:   []string{"name"},
		Values:    []any{"alpha"},
		Returning: []string{"id", "name"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if row["name"] != "alpha" {
		t.Fatalf("%+v", row)
	}
	if row["id"] == nil {
		t.Fatal("missing id")
	}
}

func TestInsertReturningRejectsBadIdent(t *testing.T) {
	sqldb, _ := sql.Open("sqlite", "file:ret2?mode=memory&cache=shared")
	_, _ = sqldb.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY)`)
	reg := db.NewRegistry()
	_ = reg.RegisterDB("main", sqldb, db.Options{AllowedTables: []string{"t"}})
	ex, _ := reg.ExecutorFor("main", core.Identity{ID: "u"}, "dev")
	_, err := ex.InsertReturning(context.Background(), db.InsertOpts{
		Table:   "t;drop",
		Columns: []string{"id"},
		Values:  []any{1},
	})
	if err == nil {
		t.Fatal("bad table must fail")
	}
}

// Regression: SQLite InsertReturning previously ran INSERT and the
// last_insert_rowid() SELECT on different pooled connections, so under
// concurrency it returned the wrong row or no row at all. Both statements
// must now run on one dedicated connection.
func TestInsertReturningSQLiteConcurrent(t *testing.T) {
	sqldb, err := sql.Open("sqlite", "file:retconc?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	sqldb.SetMaxOpenConns(8) // >1 so a wrong implementation can pick other conns
	_, _ = sqldb.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`)

	reg := db.NewRegistry()
	if err := reg.RegisterDB("main", sqldb, db.Options{
		DriverName:    "sqlite",
		Dialect:       db.DialectSQLite,
		AllowedTables: []string{"items"},
	}); err != nil {
		t.Fatal(err)
	}
	ex, err := reg.ExecutorFor("main", core.Identity{ID: "u"}, "dev")
	if err != nil {
		t.Fatal(err)
	}

	const workers = 24
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	ids := make(chan any, workers)
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("item-%d", i)
			row, err := ex.InsertReturning(context.Background(), db.InsertOpts{
				Table:     "items",
				Columns:   []string{"name"},
				Values:    []any{name},
				Returning: []string{"id", "name"},
			})
			if err != nil {
				errs <- err
				return
			}
			if row["name"] != name {
				errs <- fmt.Errorf("worker %d got row for %v", i, row["name"])
				return
			}
			ids <- row["id"]
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[any]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate returned id %v", id)
		}
		seen[id] = true
	}
	if len(seen) != workers {
		t.Fatalf("got %d ids, want %d", len(seen), workers)
	}
	var n int
	if err := sqldb.QueryRow(`SELECT COUNT(*) FROM items`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != workers {
		t.Fatalf("inserted %d rows, want %d", n, workers)
	}
}
