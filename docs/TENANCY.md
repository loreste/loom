# Tenant isolation (boundaries + databases)

Loom enforces **application-layer** isolation via `BoundaryID`, policy, and
resource ACLs. It does **not** automatically rewrite SQL with a tenant predicate
or enable Postgres RLS for you.

## What Loom guarantees

| Layer | Behavior |
|-------|----------|
| Boundary membership | Principal must be granted the request boundary |
| Policy | Explicit allow rules (often scoped to boundary) |
| Resource ACL | `type`/`id` grants per principal + boundary |
| DB pool pin | Optional `AllowedBoundaries` on a pool |
| Table allowlist | Optional `AllowedTables` on a pool |
| SQL class | Fail-closed classifier (no DDL/multi-stmt/…) |

## What you must still design

**Row-level multi-tenancy** when many tenants share one schema/table:

1. **Preferred: pool or schema per tenant** (or per boundary group)
2. **Or: Postgres RLS** with `SET LOCAL app.boundary = …` in handlers before queries
3. **Never** rely on Loom alone if `SELECT * FROM orders` can return other tenants’ rows

## Pattern A — Pool per boundary (embed)

```go
a.OpenDB("tenant_acme", "pgx", dsnAcme, db.Options{
    AllowedTables:     []string{"orders"},
    AllowedBoundaries: []core.BoundaryID{"acme"},
})
a.OpenDB("tenant_globex", "pgx", dsnGlobex, db.Options{
    AllowedTables:     []string{"orders"},
    AllowedBoundaries: []core.BoundaryID{"globex"},
})
// Handlers pick pool from identity.Boundary — never from untrusted input alone.
```

## Pattern B — Shared DB + RLS (Postgres)

At process start (migrations / superuser):

```sql
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_boundary ON orders
  USING (boundary_id = current_setting('app.boundary', true));
```

In the product handler (after Loom has authorized the call):

```go
ex, err := deps.DBs.ExecutorFor(pool, ec.Identity, ec.Boundary)
// Use a short transaction; set session GUC then query via Executor.
_, err = ex.Exec(ctx, `SELECT set_config('app.boundary', ?, true)`, string(ec.Boundary))
// Then fixed parameterized SQL only — still through Executor / SQL guard.
```

Notes:

- Use a **non-superuser** app role that cannot bypass RLS.
- `set_config` must not be exposable via free-form `db.query` to untrusted clients.
- Prefer product ops (`order.list`) over governed free-form SQL for multi-tenant apps.

## Pattern C — Product ops only (recommended)

Callers never send SQL. Handlers hard-code parameterized statements and always
filter by `ec.Boundary` / `ec.Identity.ID`:

```go
ex.Query(ctx, `SELECT id, sku FROM orders WHERE boundary = ? AND id = ?`,
    string(ec.Boundary), orderID)
```

This is the default path for `domains/orders` and `examples/orders-app`.

## Checklist

- [ ] Every durable table has a tenant/boundary column **or** lives in a tenant-scoped DB
- [ ] Handlers never take pool name solely from client input without allowlisting
- [ ] `db.query` / `db.exec` not granted to end-user product principals
- [ ] Production: `LOOM_DISABLE_DEMO_PRINCIPALS=true`, durable stores, strong JWT secret
