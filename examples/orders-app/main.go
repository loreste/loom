// Command orders-app: build a product domain with Loom + SQLite, no HTTP API.
//
// Callers never send SQL. They call order.create / order.get / order.list.
// Handlers use guarded DB executors with fixed parameterized statements.
//
//	go run ./examples/orders-app/
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
	"github.com/loreste/loom/domains/orders"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	a, err := app.New(app.Config{})
	if err != nil {
		return err
	}
	defer a.Close()

	sqldb, err := sql.Open("sqlite", "file:ordersapp?mode=memory&cache=shared")
	if err != nil {
		return err
	}
	defer sqldb.Close()
	if _, err := sqldb.Exec(orders.SchemaSQL); err != nil {
		return err
	}
	if err := a.DBs.RegisterDB("main", sqldb, db.Options{
		AllowedTables:     []string{"orders"},
		AllowedBoundaries: []core.BoundaryID{"dev"},
		MaxRows:           100,
	}); err != nil {
		return err
	}

	// Product ops (not raw SQL ops)
	if err := orders.Register(a.Registry, orders.Deps{DBs: a.DBs, Pool: "main"}); err != nil {
		return err
	}

	// Service identity — only order.* caps, no db.query/db.exec (cannot free-form SQL)
	if err := a.AddUser("svc:checkout", "checkout-token", "dev", []string{
		"order.create", "order.read",
	}); err != nil {
		return err
	}
	_ = a.GrantOp("svc:checkout", "dev", "order.create", "order", "*",
		[]string{"id", "customer", "sku", "qty", "status", "created_at"})
	_ = a.GrantOp("svc:checkout", "dev", "order.get", "order", "*",
		[]string{"id", "customer", "sku", "qty", "status", "created_at"})
	_ = a.GrantOp("svc:checkout", "dev", "order.list", "order", "*",
		[]string{"orders", "count"})

	// Create
	created := a.Call(ctx, core.Request{
		Operation:   "order.create",
		Credentials: core.Credentials{Token: "checkout-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "order", ID: "*"},
		Input: map[string]any{
			"customer": "acme",
			"sku":      "SKU-100",
			"qty":      3,
		},
		IdempotencyKey: "ord-1",
	})
	printJSON("order.create", created)
	if !created.Allowed {
		return fmt.Errorf("create denied: %v", created.Denial)
	}

	id := created.Output["id"]
	got := a.Call(ctx, core.Request{
		Operation:   "order.get",
		Credentials: core.Credentials{Token: "checkout-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "order", ID: fmt.Sprint(id)},
		Input:       map[string]any{"id": id},
	})
	printJSON("order.get", got)

	listed := a.Call(ctx, core.Request{
		Operation:   "order.list",
		Credentials: core.Credentials{Token: "checkout-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "order", ID: "*"},
		Input:       map[string]any{"customer": "acme"},
	})
	printJSON("order.list", listed)

	// Free-form SQL is not even registered for this service — and if someone
	// enabled db.query, this principal lacks capability.
	sneak := a.Call(ctx, core.Request{
		Operation:   "db.query",
		Credentials: core.Credentials{Token: "checkout-token"},
		Boundary:    "dev",
		Input:       map[string]any{"pool": "main", "sql": "SELECT * FROM orders"},
	})
	printJSON("sneak db.query (expect deny)", sneak)
	return nil
}

func printJSON(label string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Printf("== %s ==\n%s\n", label, b)
}
