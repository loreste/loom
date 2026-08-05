package job_test

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
	"github.com/loreste/loom/domains/orders"
	"github.com/loreste/loom/job"
)

func TestSQLQueueDurableThroughLoom(t *testing.T) {
	ctx := context.Background()
	sqldb, err := sql.Open("sqlite", "file:sqlqueue?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })

	// App + orders schema on same DB as the queue (typical embed worker).
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	mig := db.NewMigrator(sqldb, db.DialectSQLite)
	if err := mig.Apply(ctx, orders.Migrations()); err != nil {
		t.Fatal(err)
	}
	_ = a.DBs.RegisterDB("main", sqldb, db.Options{
		DriverName: "sqlite", Dialect: db.DialectSQLite, AllowedTables: []string{"orders"},
	})
	_ = orders.Register(a.Registry, orders.Deps{DBs: a.DBs, Pool: "main"})
	_ = a.AddUser("svc:worker", "tok", "dev", []string{"order.create", "order.read"})
	_ = a.GrantOp("svc:worker", "dev", "order.create", "order", "*",
		[]string{"id", "customer", "sku", "qty", "status", "created_at"})

	q, err := job.NewSQLQueue(ctx, sqldb, job.SQLQueueOptions{Dialect: db.DialectSQLite})
	if err != nil {
		t.Fatal(err)
	}
	// Approval token must not be required to persist — and must be dropped if set.
	if err := q.Enqueue(ctx, job.Job{
		ID:        "j-sql-1",
		Operation: "order.create",
		Boundary:  "dev",
		Resource:  &core.ResourceRef{Type: "order", ID: "*"},
		Input:     map[string]any{"customer": "c", "sku": "S", "qty": 1},
		// ApprovalToken intentionally ignored by SQLQueue
		ApprovalToken: "should-not-be-stored",
	}); err != nil {
		t.Fatal(err)
	}
	n, err := q.PendingCount(ctx)
	if err != nil || n != 1 {
		t.Fatalf("pending=%d err=%v", n, err)
	}

	r := &job.Runner{Queue: q, Caller: a, Token: "tok"}
	res, ok, err := r.ProcessOne(ctx)
	if err != nil || !ok {
		t.Fatalf("err=%v ok=%v", err, ok)
	}
	if !res.Response.Allowed {
		t.Fatalf("%+v", res.Response.Denial)
	}

	// Second poll empty
	_, ok, err = r.ProcessOne(ctx)
	if err != nil || ok {
		t.Fatalf("expected empty queue, ok=%v err=%v", ok, err)
	}
	n, _ = q.PendingCount(ctx)
	if n != 0 {
		t.Fatalf("pending after drain=%d", n)
	}

	// Ensure approval token was not written into the jobs table.
	var cnt int
	err = sqldb.QueryRow(`SELECT COUNT(*) FROM loom_jobs`).Scan(&cnt)
	if err != nil {
		t.Fatal(err)
	}
	// row still exists as done
	if cnt != 1 {
		t.Fatalf("rows=%d", cnt)
	}
	// table must not have an approval column
	rows, err := sqldb.Query(`PRAGMA table_info(loom_jobs)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if name == "approval_token" {
			t.Fatal("approval_token column must not exist")
		}
	}
}

func TestSQLQueueRejectsBadTableName(t *testing.T) {
	sqldb, _ := sql.Open("sqlite", "file:badtbl?mode=memory&cache=shared")
	t.Cleanup(func() { _ = sqldb.Close() })
	_, err := job.NewSQLQueue(context.Background(), sqldb, job.SQLQueueOptions{
		Table: "jobs; drop table",
	})
	if err == nil {
		t.Fatal("expected invalid table name")
	}
}

func TestSQLQueueEmptyPoll(t *testing.T) {
	sqldb, _ := sql.Open("sqlite", "file:emptypoll?mode=memory&cache=shared")
	t.Cleanup(func() { _ = sqldb.Close() })
	q, err := job.NewSQLQueue(context.Background(), sqldb, job.SQLQueueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := q.Poll(context.Background())
	if err != nil || ok {
		t.Fatalf("empty poll ok=%v err=%v", ok, err)
	}
}
