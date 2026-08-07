package orders_test

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
	"github.com/loreste/loom/domains/orders"
)

func TestOrdersDomainNoRawSQLCapability(t *testing.T) {
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	sqldb, _ := sql.Open("sqlite", "file:ordertest?mode=memory&cache=shared")
	_, _ = sqldb.Exec(orders.SchemaSQL)
	_ = a.DBs.RegisterDB("main", sqldb, db.Options{
		AllowedTables: []string{"orders"},
	})
	_ = orders.Register(a.Registry, orders.Deps{DBs: a.DBs, Pool: "main"})
	_ = a.AddUser("svc:api", "tok", "dev", []string{"order.create", "order.read"})
	_ = a.GrantOp("svc:api", "dev", "order.create", "order", "*", []string{"id", "customer", "sku", "qty", "status", "created_at"})
	_ = a.GrantOp("svc:api", "dev", "order.get", "order", "*", []string{"id", "customer", "sku", "qty", "status", "created_at"})
	_ = a.GrantOp("svc:api", "dev", "order.list", "order", "*", []string{"orders", "count"})
	// intentionally do NOT enable db.query for this principal

	resp := a.Call(context.Background(), core.Request{
		Operation:      "order.create",
		Credentials:    core.Credentials{Token: "tok"},
		Boundary:       "dev",
		Resource:       &core.ResourceRef{Type: "order", ID: "*"},
		Input:          map[string]any{"customer": "c1", "sku": "S1", "qty": 2},
		IdempotencyKey: "o1",
	})
	if !resp.Allowed {
		t.Fatalf("%+v", resp.Denial)
	}

	list := a.Call(context.Background(), core.Request{
		Operation:   "order.list",
		Credentials: core.Credentials{Token: "tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "order", ID: "*"},
		Input:       map[string]any{},
	})
	if !list.Allowed {
		t.Fatalf("%+v", list.Denial)
	}
	if list.Output["count"] != 1 {
		t.Fatalf("%+v", list.Output)
	}
}
