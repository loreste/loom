package db_test

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
)

func TestTenantRequiredPoolRejectsUnboundAccess(t *testing.T) {
	sqldb, err := sql.Open("sqlite", "file:tenant-required?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if _, err := sqldb.Exec(`CREATE TABLE orders (id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	reg := db.NewRegistry()
	if err := reg.RegisterDB("main", sqldb, db.Options{
		Dialect:              db.DialectSQLite,
		AllowedTables:        []string{"orders"},
		RequireTenantContext: true,
	}); err != nil {
		t.Fatal(err)
	}
	ex, err := reg.ExecutorFor("main", core.Identity{ID: "user:a"}, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ex.Query(context.Background(), `SELECT id FROM orders`); err == nil {
		t.Fatal("direct query must be rejected for tenant-bound pool")
	}
	if _, err := ex.Begin(context.Background()); err == nil {
		t.Fatal("unbound transaction must be rejected for tenant-bound pool")
	}
	if _, err := ex.BeginTenant(context.Background()); err == nil {
		t.Fatal("non-Postgres tenant RLS transaction must be rejected")
	}
}

func TestTenantSettingMustBeApplicationScoped(t *testing.T) {
	sqldb, err := sql.Open("sqlite", "file:tenant-setting?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	reg := db.NewRegistry()
	if err := reg.RegisterDB("main", sqldb, db.Options{
		Dialect:              db.DialectPostgres,
		RequireTenantContext: true,
		TenantSetting:        "search_path",
	}); err == nil {
		t.Fatal("unsafe tenant setting must be rejected")
	}
}
