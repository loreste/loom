// Package orders is an example domain: product ops that use Loom-governed DB access
// without exposing raw SQL to callers (callers invoke order.create / order.get).
package orders

import (
	"fmt"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
)

const (
	OpCreate = "order.create"
	OpGet    = "order.get"
	OpList   = "order.list"
)

// Deps for order handlers.
type Deps struct {
	// DBs registry; pool name defaults to "main".
	DBs  *db.Registry
	Pool string
}

// Register wires order operations. Tables expected: orders(id, customer, sku, qty, status, created_at).
func Register(reg *core.Registry, deps Deps) error {
	if reg == nil || deps.DBs == nil {
		return fmt.Errorf("%w: registry and dbs required", core.ErrInvalidArgument)
	}
	if deps.Pool == "" {
		deps.Pool = "main"
	}

	createSchema := []byte(`{
		"type":"object",
		"properties":{
			"customer":{"type":"string","minLength":1,"maxLength":128},
			"sku":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9_-]+$"},
			"qty":{"type":"integer","minimum":1,"maximum":10000}
		},
		"required":["customer","sku","qty"],
		"additionalProperties":false
	}`)
	if err := reg.Register(&core.Operation{
		Name:        OpCreate,
		Description: "Create an order (parameterized insert via guarded executor)",
		InputSchema: createSchema,
		Permissions: []string{"order.create"},
		Resources:   []string{"order"},
		Risk:        core.RiskMedium,
		Effects:     []core.Effect{core.EffectWrite},
		Idempotency: core.IdempotencyPolicy{Required: true, TTLSeconds: 3600},
		Quota:       core.QuotaPolicy{Enabled: true},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handleCreate(ec, deps)
	}); err != nil {
		return err
	}

	getSchema := []byte(`{
		"type":"object",
		"properties":{"id":{"type":"integer","minimum":1}},
		"required":["id"],
		"additionalProperties":false
	}`)
	if err := reg.Register(&core.Operation{
		Name:        OpGet,
		Description: "Get an order by id",
		InputSchema: getSchema,
		Permissions: []string{"order.read"},
		Resources:   []string{"order"},
		Risk:        core.RiskLow,
		Effects:     []core.Effect{core.EffectRead},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handleGet(ec, deps)
	}); err != nil {
		return err
	}

	listSchema := []byte(`{
		"type":"object",
		"properties":{
			"customer":{"type":"string","maxLength":128},
			"limit":{"type":"integer","minimum":1,"maximum":100}
		},
		"additionalProperties":false
	}`)
	return reg.Register(&core.Operation{
		Name:        OpList,
		Description: "List orders (optional customer filter)",
		InputSchema: listSchema,
		Permissions: []string{"order.read"},
		Resources:   []string{"order"},
		Risk:        core.RiskLow,
		Effects:     []core.Effect{core.EffectRead},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handleList(ec, deps)
	})
}

// EnsureSchema creates the orders table (sqlite/postgres-compatible subset).
// Call from app bootstrap only — not exposed as a public op by default.
func EnsureSchema(ex *db.Executor, ctx interface{ Done() <-chan struct{} }) error {
	// Use a simple create via pool's raw path is not available; use Exec after
	// temporarily... DDL is blocked by Classify. For migrations use a one-time
	// admin bootstrap outside Classify or use sql.DB at app startup before Loom.
	return fmt.Errorf("orders: run EnsureSchemaSQL on *sql.DB at process start")
}

// Migrations for process startup via db.Migrator (not via app SQL path).
func Migrations() []db.Migration {
	return []db.Migration{
		{
			Version: 1,
			Name:    "orders_init",
			Up: `CREATE TABLE IF NOT EXISTS orders (
	 id INTEGER PRIMARY KEY AUTOINCREMENT,
	 tenant_id TEXT NOT NULL,
	 customer TEXT NOT NULL,
  sku TEXT NOT NULL,
  qty INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);`,
		},
	}
}

// SchemaSQL is a convenience single-shot DDL for demos (prefer Migrations()).
const SchemaSQL = `
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 tenant_id TEXT NOT NULL,
 customer TEXT NOT NULL,
  sku TEXT NOT NULL,
  qty INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`

func handleCreate(ec *core.ExecutionContext, deps Deps) (*core.Result, error) {
	customer, _ := ec.Input["customer"].(string)
	sku, _ := ec.Input["sku"].(string)
	qty, ok := asInt(ec.Input["qty"])
	if !ok || qty < 1 {
		return nil, fmt.Errorf("invalid qty")
	}
	ex, err := deps.DBs.ExecutorFor(deps.Pool, ec.Identity, ec.Boundary)
	if err != nil {
		return nil, err
	}
	// Prefer transaction for multi-step future inventory checks.
	tx, err := ex.BeginScoped(ec.Ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)
	// Dialect-aware insert: Postgres RETURNING / SQLite last_insert_rowid.
	// Column names are fixed identifiers — never caller-controlled.
	row, err := tx.InsertReturning(ec.Ctx, db.InsertOpts{
		Table:     "orders",
		Columns:   []string{"tenant_id", "customer", "sku", "qty", "status", "created_at"},
		Values:    []any{string(ec.Boundary), customer, sku, qty, "created", now},
		Returning: []string{"id", "customer", "sku", "qty", "status", "created_at"},
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &core.Result{Output: map[string]any{
		"id":         row["id"],
		"customer":   row["customer"],
		"sku":        row["sku"],
		"qty":        row["qty"],
		"status":     row["status"],
		"created_at": row["created_at"],
	}}, nil
}

func handleGet(ec *core.ExecutionContext, deps Deps) (*core.Result, error) {
	id, ok := asInt(ec.Input["id"])
	if !ok {
		return nil, fmt.Errorf("invalid id")
	}
	// Resource-level: if resource id set, must match
	if ec.Resource != nil && ec.Resource.ID != "" && ec.Resource.ID != fmt.Sprint(id) {
		return nil, fmt.Errorf("resource id mismatch")
	}
	ex, err := deps.DBs.ExecutorFor(deps.Pool, ec.Identity, ec.Boundary)
	if err != nil {
		return nil, err
	}
	rs, err := ex.QueryScoped(ec.Ctx,
		`SELECT id, customer, sku, qty, status, created_at FROM orders WHERE tenant_id = ? AND id = ?`, string(ec.Boundary), id)
	if err != nil {
		return nil, err
	}
	if len(rs.Rows) == 0 {
		return nil, fmt.Errorf("order not found")
	}
	row := rs.Rows[0]
	return &core.Result{Output: map[string]any{
		"id": row["id"], "customer": row["customer"], "sku": row["sku"],
		"qty": row["qty"], "status": row["status"], "created_at": row["created_at"],
	}}, nil
}

func handleList(ec *core.ExecutionContext, deps Deps) (*core.Result, error) {
	limit := int64(20)
	if v, ok := asInt(ec.Input["limit"]); ok {
		limit = v
	}
	ex, err := deps.DBs.ExecutorFor(deps.Pool, ec.Identity, ec.Boundary)
	if err != nil {
		return nil, err
	}
	customer, _ := ec.Input["customer"].(string)
	var rs *db.ResultSet
	if customer != "" {
		rs, err = ex.QueryScoped(ec.Ctx,
			`SELECT id, customer, sku, qty, status, created_at FROM orders WHERE tenant_id = ? AND customer = ? ORDER BY id DESC`,
			string(ec.Boundary), customer)
	} else {
		rs, err = ex.QueryScoped(ec.Ctx,
			`SELECT id, customer, sku, qty, status, created_at FROM orders WHERE tenant_id = ? ORDER BY id DESC`, string(ec.Boundary))
	}
	if err != nil {
		return nil, err
	}
	// enforce limit in process (portable; avoids LIMIT bind dialect issues)
	rows := rs.Rows
	if int64(len(rows)) > limit {
		rows = rows[:limit]
	}
	return &core.Result{Output: map[string]any{
		"orders": rows,
		"count":  len(rows),
	}}, nil
}

func asInt(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case int:
		return int64(t), true
	default:
		return 0, false
	}
}
