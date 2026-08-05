// Command orders-app: build a product domain with Loom + SQLite, no HTTP API.
//
// Callers never send SQL. They call order.create / order.get / order.list.
// Handlers use guarded DB executors with fixed parameterized statements.
//
//	go run ./examples/orders-app/
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/config"
	"github.com/loreste/loom/core"
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

	// One-shot: migrate → open pool → register domain → seed least-privilege user.
	res, err := app.Bootstrap(ctx, app.BootstrapConfig{
		DB: &config.AppDB{
			URL:        "file:ordersapp?mode=memory&cache=shared",
			Driver:     "sqlite",
			Pool:       "main",
			Tables:     []string{"orders"},
			Boundaries: []core.BoundaryID{"dev"},
			MaxRows:    100,
		},
		Migrations: orders.Migrations(),
		Setup: func(a *app.App, pool string) error {
			return orders.Register(a.Registry, orders.Deps{DBs: a.DBs, Pool: pool})
		},
		Users: []app.SeedUser{{
			ID: "svc:checkout", Token: "checkout-token", Home: "dev",
			Caps: []string{"order.create", "order.read"},
			Ops: []app.SeedOp{
				{Op: "order.create", ResType: "order", ResID: "*",
					Fields: []string{"id", "customer", "sku", "qty", "status", "created_at"}},
				{Op: "order.get", ResType: "order", ResID: "*",
					Fields: []string{"id", "customer", "sku", "qty", "status", "created_at"}},
				{Op: "order.list", ResType: "order", ResID: "*",
					Fields: []string{"orders", "count"}},
			},
		}},
	})
	if err != nil {
		return err
	}
	defer res.App.Close()
	a := res.App

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
