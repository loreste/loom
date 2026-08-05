package db_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/resource"
)

func TestEmbedAppDBQueryAndExec(t *testing.T) {
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	sqldb, err := sql.Open("sqlite", "file:loomtest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if _, err := sqldb.Exec(`CREATE TABLE orders (id INTEGER PRIMARY KEY, item TEXT, amount REAL)`); err != nil {
		t.Fatal(err)
	}

	if err := a.DBs.RegisterDB("main", sqldb, db.Options{
		AllowedTables:     []string{"orders"},
		AllowedBoundaries: []core.BoundaryID{"dev"},
		MaxRows:           100,
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.EnableDBOps(); err != nil {
		t.Fatal(err)
	}

	// Principal with db caps
	if err := a.AddUser("user:app", "app-token", "dev", []string{"db.query", "db.exec"}); err != nil {
		t.Fatal(err)
	}
	_ = a.AllowPolicy(policy.Rule{Principal: "user:app", Boundary: "dev", Operation: "db.query", Priority: 10})
	_ = a.AllowPolicy(policy.Rule{Principal: "user:app", Boundary: "dev", Operation: "db.exec", Priority: 10})
	_ = a.AllowResource(resource.Rule{
		Principal: "user:app", Boundary: "dev", Type: "db", ID: "main",
		Operations: []string{"db.query", "db.exec"},
	})
	_ = a.AllowFields("user:app", "dev", "db.query", []string{"pool", "columns", "rows", "count", "truncated"})
	_ = a.AllowFields("user:app", "dev", "db.exec", []string{"pool", "rows_affected", "status"})

	// insert needs approval (high risk)
	_ = a.IssueApproval("appr-db", "user:app", "db.exec", "dev", core.RiskCritical, time.Hour)

	execResp := a.Call(context.Background(), core.Request{
		Operation:   "db.exec",
		Credentials: core.Credentials{Token: "app-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "db", ID: "main"},
		Input: map[string]any{
			"pool": "main",
			"sql":  "INSERT INTO orders (item, amount) VALUES (?, ?)",
			"args": []any{"widget", 9.5},
		},
		IdempotencyKey: "ins-1",
		ApprovalToken:  "appr-db",
	})
	if !execResp.Allowed {
		t.Fatalf("exec: %+v", execResp.Denial)
	}

	qResp := a.Call(context.Background(), core.Request{
		Operation:   "db.query",
		Credentials: core.Credentials{Token: "app-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "db", ID: "main"},
		Input: map[string]any{
			"pool": "main",
			"sql":  "SELECT item, amount FROM orders WHERE amount > ?",
			"args": []any{1.0},
		},
	})
	if !qResp.Allowed {
		t.Fatalf("query: %+v", qResp.Denial)
	}
	switch n := qResp.Output["count"].(type) {
	case int:
		if n != 1 {
			t.Fatalf("count=%d output=%+v", n, qResp.Output)
		}
	case int64:
		if n != 1 {
			t.Fatalf("count=%d output=%+v", n, qResp.Output)
		}
	default:
		t.Fatalf("unexpected count type %T in %+v", qResp.Output["count"], qResp.Output)
	}

	// table not allowlisted
	bad := a.Call(context.Background(), core.Request{
		Operation:   "db.query",
		Credentials: core.Credentials{Token: "app-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "db", ID: "main"},
		Input: map[string]any{
			"pool": "main",
			"sql":  "SELECT * FROM secrets",
		},
	})
	if bad.Allowed {
		t.Fatal("secrets table must deny")
	}

	// multi-statement blocked
	bad2 := a.Call(context.Background(), core.Request{
		Operation:   "db.query",
		Credentials: core.Credentials{Token: "app-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "db", ID: "main"},
		Input: map[string]any{
			"pool": "main",
			"sql":  "SELECT 1; SELECT 2",
		},
	})
	if bad2.Allowed {
		t.Fatal("multi-statement must deny")
	}

	// no token
	unauth := a.Call(context.Background(), core.Request{
		Operation: "db.query",
		Boundary:  "dev",
		Input:     map[string]any{"pool": "main", "sql": "SELECT 1"},
	})
	if unauth.Allowed {
		t.Fatal("unauthenticated must deny")
	}
}

func TestHandlerCannotGetRawSQLInjectionThroughGuard(t *testing.T) {
	a, _ := app.New(app.Config{})
	t.Cleanup(func() { _ = a.Close() })
	sqldb, _ := sql.Open("sqlite", "file:inj?mode=memory&cache=shared")
	_, _ = sqldb.Exec(`CREATE TABLE t (id INT)`)
	_ = a.DBs.RegisterDB("main", sqldb, db.Options{})
	_ = a.AddUser("u", "tok", "dev", []string{"db.query"})
	_ = a.AllowPolicy(policy.Rule{Principal: "u", Boundary: "dev", Operation: "db.query", Priority: 1})
	_ = a.AllowResource(resource.Rule{Principal: "u", Boundary: "dev", Type: "db", ID: "*", Operations: []string{"db.query"}})
	_ = a.AllowFields("u", "dev", "db.query", []string{"*"})
	_ = a.EnableDBOps()

	resp := a.Call(context.Background(), core.Request{
		Operation:   "db.query",
		Credentials: core.Credentials{Token: "tok"},
		Boundary:    "dev",
		Input: map[string]any{
			"pool": "main",
			"sql":  "SELECT * FROM t WHERE id = 1 OR 1=1 --",
		},
	})
	if resp.Allowed {
		t.Fatal("comment injection must fail closed")
	}
}
