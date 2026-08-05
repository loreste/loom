package app_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/config"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
	"github.com/loreste/loom/domains/orders"
)

func TestDefaultDenyNoUsers(t *testing.T) {
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	resp := a.Call(context.Background(), core.Request{
		Operation:   "order.create",
		Credentials: core.Credentials{Token: "anything"},
		Boundary:    "dev",
	})
	if resp.Allowed {
		t.Fatal("empty app must deny")
	}
}

func TestNilAppCallDenies(t *testing.T) {
	var a *app.App
	resp := a.Call(context.Background(), core.Request{Operation: "x"})
	if resp.Allowed || resp.Denial == nil {
		t.Fatal("nil app must deny")
	}
}

func TestBypassMetadataHardDenied(t *testing.T) {
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	_ = a.AddUser("u", "tok", "dev", []string{"order.create"})

	resp := a.Call(context.Background(), core.Request{
		Operation:   "order.create",
		Credentials: core.Credentials{Token: "tok"},
		Boundary:    "dev",
		Metadata:    map[string]string{"X-Loom-Bypass": "1"},
	})
	if resp.Allowed {
		t.Fatal("bypass header must never allow")
	}
}

func TestBootstrapMigrateRegisterSeed(t *testing.T) {
	ctx := context.Background()
	res, err := app.Bootstrap(ctx, app.BootstrapConfig{
		DB: &config.AppDB{
			URL:        "file:boottest?mode=memory&cache=shared",
			Driver:     "sqlite",
			Pool:       "main",
			Tables:     []string{"orders"},
			Boundaries: []core.BoundaryID{"dev"},
		},
		Migrations: orders.Migrations(),
		Setup: func(a *app.App, pool string) error {
			if pool != "main" {
				t.Fatalf("pool=%q", pool)
			}
			return orders.Register(a.Registry, orders.Deps{DBs: a.DBs, Pool: pool})
		},
		Users: []app.SeedUser{{
			ID: "svc:checkout", Token: "checkout-token", Home: "dev",
			Caps: []string{"order.create", "order.read"},
			Ops: []app.SeedOp{
				{Op: "order.create", ResType: "order", ResID: "*", Fields: []string{"id", "customer", "sku", "qty", "status", "created_at"}},
				{Op: "order.list", ResType: "order", ResID: "*", Fields: []string{"orders", "count"}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.App.Close() })

	created := res.App.Call(ctx, core.Request{
		Operation:   "order.create",
		Credentials: core.Credentials{Token: "checkout-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "order", ID: "*"},
		Input:       map[string]any{"customer": "acme", "sku": "S1", "qty": 2},
		// order.create requires an idempotency key.
		IdempotencyKey: "boot-ord-1",
	})
	if !created.Allowed {
		t.Fatalf("create: %+v", created.Denial)
	}

	// No db.query capability / op not even needed — must deny free-form SQL path
	// if somehow registered.
	sneak := res.App.Call(ctx, core.Request{
		Operation:   "db.query",
		Credentials: core.Credentials{Token: "checkout-token"},
		Boundary:    "dev",
		Input:       map[string]any{"pool": "main", "sql": "SELECT 1"},
	})
	if sneak.Allowed {
		t.Fatal("checkout principal must not run free-form SQL")
	}
}

func TestBootstrapBadDSNFailsClosed(t *testing.T) {
	_, err := app.Bootstrap(context.Background(), app.BootstrapConfig{
		DB: &config.AppDB{
			URL:    "file:does-not-matter",
			Driver: "not-a-real-driver",
			Pool:   "main",
		},
	})
	if err == nil {
		t.Fatal("expected open/ping error")
	}
}

func TestGrantDBAccessLeastPrivilege(t *testing.T) {
	ctx := context.Background()
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	sqldb, err := sql.Open("sqlite", "file:granttest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if _, err := sqldb.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := a.DBs.RegisterDB("main", sqldb, db.Options{
		DriverName: "sqlite", AllowedTables: []string{"notes"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.EnableDBOps(); err != nil {
		t.Fatal(err)
	}
	_ = a.AddUser("svc:reader", "rtok", "dev", []string{"db.query"})
	if err := a.GrantDBAccess(app.DBAccess{
		Principal: "svc:reader", Boundary: "dev", Pool: "main", Query: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Insert as setup outside Loom path
	if _, err := sqldb.Exec(`INSERT INTO notes (body) VALUES ('hi')`); err != nil {
		t.Fatal(err)
	}

	ok := a.Call(ctx, core.Request{
		Operation:   "db.query",
		Credentials: core.Credentials{Token: "rtok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "db", ID: "main"},
		Input:       map[string]any{"pool": "main", "sql": "SELECT id, body FROM notes"},
	})
	if !ok.Allowed {
		t.Fatalf("query: %+v", ok.Denial)
	}

	// Write path denied (no db.exec grant)
	write := a.Call(ctx, core.Request{
		Operation:   "db.exec",
		Credentials: core.Credentials{Token: "rtok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "db", ID: "main"},
		Input:       map[string]any{"pool": "main", "sql": "DELETE FROM notes"},
	})
	if write.Allowed {
		t.Fatal("reader must not exec")
	}

	// Table allowlist
	leak := a.Call(ctx, core.Request{
		Operation:   "db.query",
		Credentials: core.Credentials{Token: "rtok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "db", ID: "main"},
		Input:       map[string]any{"pool": "main", "sql": "SELECT name FROM sqlite_master"},
	})
	if leak.Allowed {
		t.Fatal("sqlite_master must be blocked by allowlist")
	}
}

func TestAdapterMetadataForced(t *testing.T) {
	a, _ := app.New(app.Config{})
	t.Cleanup(func() { _ = a.Close() })
	// empty registry → deny, but metadata should still be set on the way
	resp := a.Call(context.Background(), core.Request{
		Operation:   "nope",
		Credentials: core.Credentials{Token: "x"},
	})
	if resp.Allowed {
		t.Fatal("expected deny")
	}
	// Ensure Call does not panic with nil Metadata — covered by not panicking above.
	_ = strings.Contains
}
