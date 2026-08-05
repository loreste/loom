package db_test

import (
	"testing"

	"github.com/loreste/loom/db"
)

func TestRebindPostgres(t *testing.T) {
	q, err := db.Rebind(db.DialectPostgres, `INSERT INTO t (a, b) VALUES (?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	if q != `INSERT INTO t (a, b) VALUES ($1, $2)` {
		t.Fatal(q)
	}
	// ignore ? inside strings
	q, _ = db.Rebind(db.DialectPostgres, `SELECT '?' FROM t WHERE id = ?`)
	if q != `SELECT '?' FROM t WHERE id = $1` {
		t.Fatal(q)
	}
}

func TestRebindSQLiteNoop(t *testing.T) {
	in := `SELECT * FROM t WHERE id = ?`
	q, err := db.Rebind(db.DialectSQLite, in)
	if err != nil || q != in {
		t.Fatalf("%v %q", err, q)
	}
}

func TestDetectDialect(t *testing.T) {
	if db.DetectDialect("pgx") != db.DialectPostgres {
		t.Fatal("pgx")
	}
	if db.DetectDialect("sqlite") != db.DialectSQLite {
		t.Fatal("sqlite")
	}
}
