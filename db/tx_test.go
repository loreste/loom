package db_test

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
)

func TestTxCommitAndRollback(t *testing.T) {
	sqldb, err := sql.Open("sqlite", "file:txtest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	_, _ = sqldb.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`)

	reg := db.NewRegistry()
	_ = reg.RegisterDB("main", sqldb, db.Options{AllowedTables: []string{"t"}})
	ex, err := reg.ExecutorFor("main", core.Identity{ID: "u"}, "dev")
	if err != nil {
		t.Fatal(err)
	}

	tx, err := ex.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `INSERT INTO t (v) VALUES (?)`, "a"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rs, err := ex.Query(context.Background(), `SELECT v FROM t`)
	if err != nil || len(rs.Rows) != 1 {
		t.Fatalf("%v %+v", err, rs)
	}

	tx2, _ := ex.Begin(context.Background())
	_, _ = tx2.Exec(context.Background(), `INSERT INTO t (v) VALUES (?)`, "b")
	_ = tx2.Rollback()
	rs, _ = ex.Query(context.Background(), `SELECT v FROM t`)
	if len(rs.Rows) != 1 {
		t.Fatalf("rollback failed: %d rows", len(rs.Rows))
	}
}

func TestTxRejectsBadSQL(t *testing.T) {
	sqldb, _ := sql.Open("sqlite", "file:txtest2?mode=memory&cache=shared")
	_, _ = sqldb.Exec(`CREATE TABLE t (id INT)`)
	reg := db.NewRegistry()
	_ = reg.RegisterDB("main", sqldb, db.Options{AllowedTables: []string{"t"}})
	ex, _ := reg.ExecutorFor("main", core.Identity{ID: "u"}, "dev")
	tx, _ := ex.Begin(context.Background())
	defer tx.Rollback()
	if _, err := tx.Exec(context.Background(), `DROP TABLE t`); err == nil {
		t.Fatal("ddl must fail")
	}
}
