# Building with Loom (no API required)

## Goal

Ship product features with **identity, authorization, and safe database access** without designing a custom authz microservice or exposing SQL to clients.

## Pattern A — Product operations (recommended)

Callers never see SQL. Handlers use fixed parameterized statements via `db.Executor`.

```text
client / worker
    → app.Call("order.create", …)
        → policy/authz
        → handler uses Executor (fixed SQL)
        → database
```

See `examples/orders-app/` and `domains/orders`.

## Pattern B — Governed SQL ops

Power-user / admin tooling may use `db.query` / `db.exec` with:

- capability `db.query` / `db.exec`
- policy allow rules
- resource ACL on `db:<pool>`
- SQL classifier (no multi-statement, comments, DDL, …)
- optional table allowlist

See `examples/embed/`.

## Pattern C — Optional network edge

When you need remote callers, attach HTTP:

```bash
go run ./cmd/loom serve --addr=:8080
```

Same `Runtime.Execute` path. Remote SDKs cannot grant themselves power.

### Discovery (optional network edge)

Clients can discover how to call a Loom service without a hand-rolled API catalog:

1. `GET /.well-known/loom.json` — static discovery (unauthenticated; no operation list).
2. `GET /v1/openapi.json` — OpenAPI 3 filtered to the caller's capabilities.
3. `catalog.spec` via `POST /v1/execute` — tool-style specs (schema, risk, approval,
   idempotency) for ops the caller can use.
4. Optionally `POST /mcp` for `tools/list` + `tools/call` (same pipeline).
5. Invoke via `POST /v1/execute`. Denials use stable `reason` codes plus optional
   `hint` / `retryable`; internal detail stays in audit only.


## Connecting databases

| Driver | Import | `OpenDB` driver name |
|--------|--------|----------------------|
| Postgres | `_ "github.com/jackc/pgx/v5/stdlib"` | `pgx` |
| SQLite (pure Go) | `_ "modernc.org/sqlite"` | `sqlite` |

```go
a.OpenDB("primary", "pgx", os.Getenv("DATABASE_URL"), db.Options{
    AllowedTables:     []string{"public.orders", "public.order_items"},
    AllowedBoundaries: []core.BoundaryID{"prod"},
    StatementTimeout:  5 * time.Second,
    MaxRows:           500,
    ReadOnly:          false,
})
```

**Migrations / DDL** run at process startup on `*sql.DB` *before* registering with Loom (DDL is blocked in app SQL path by design).

```go
mig := db.NewMigrator(sqldb, db.DialectSQLite) // or DialectPostgres
_ = mig.Apply(ctx, orders.Migrations())
a.DBs.RegisterDB("main", sqldb, db.Options{DriverName: "sqlite", AllowedTables: []string{"orders"}})
```

### Placeholders

Write SQL with `?`. Loom rebinds automatically:

| Dialect | Driver examples | Bound form |
|---------|-----------------|------------|
| SQLite | `sqlite` | `?` |
| Postgres | `pgx`, `postgres` | `$1`, `$2`, … |

```go
// works on both after Rebind inside Executor
ex.Exec(ctx, `INSERT INTO orders (sku) VALUES (?)`, sku)
```

### One-shot bootstrap

```go
res, err := app.Bootstrap(ctx, app.BootstrapConfig{
    DB: &config.AppDB{
        URL: "file:app.db", Driver: "sqlite", Pool: "main",
        Tables: []string{"orders"}, Boundaries: []core.BoundaryID{"dev"},
    },
    Migrations: orders.Migrations(),
    Setup: func(a *app.App, pool string) error {
        return orders.Register(a.Registry, orders.Deps{DBs: a.DBs, Pool: pool})
    },
    Users: []app.SeedUser{{
        ID: "svc:api", Token: token, Home: "dev",
        Caps: []string{"order.create", "order.read"},
        Ops: []app.SeedOp{{
            Op: "order.create", ResType: "order", ResID: "*",
            Fields: []string{"id", "customer", "sku", "qty", "status", "created_at"},
        }},
    }},
})
defer res.App.Close()
```

Or set `OpenDBFromEnv: true` to load `LOOM_APP_DB_*`.

### Worker processes & job queue

Long-running workers use the same embed path — see `examples/worker/`.

```go
// In-process FIFO
q := job.NewMemoryQueue()
// Durable SQLite/Postgres (approval tokens are never persisted)
q, _ := job.NewSQLQueue(ctx, sqldb, job.SQLQueueOptions{Dialect: db.DialectSQLite})

_ = q.Enqueue(ctx, job.Job{ID: "1", Operation: "order.create", Boundary: "dev", Input: ...})
runner := &job.Runner{Queue: q, Caller: app, Token: serviceToken}
_ = runner.Run(ctx) // each job → app.Call (full pipeline)
```

Jobs are **not** a privilege bypass: denied ops still deny.

### Optional adapters (same pipeline)

| Edge | Path / API | Notes |
|------|------------|--------|
| HTTP | `POST /v1/execute` | Primary remote surface |
| MCP | `POST /mcp` | JSON-RPC tools/list + tools/call |
| GraphQL | `POST /graphql` | `mutation { execute(input: …) }` |
| gRPC | `loom.v1.Runtime/Execute` | Proto in `adapters/grpc/proto` |
| Weft | in-process adapter | Optional |

None of these can bypass `Runtime.Execute`.

### MCP wire (optional agent edge)

JSON-RPC 2.0 tools/list + tools/call over stdio **or** `POST /mcp` on the HTTP edge — same pipeline:

```go
srv := &mcp.Server{
    Adapter: mcp.New(a.Runtime), Registry: a.Registry, Verifier: a.Verifier,
    Token: os.Getenv("LOOM_TOKEN"), Boundary: "dev",
}
_ = srv.ServeStream(ctx, os.Stdin, os.Stdout)
```

When serving HTTP via `cmd/loom serve` / platform CLI, `POST /mcp` and
`GET /v1/openapi.json` are wired automatically.

`tools/list` and OpenAPI are capability-filtered (empty tool paths without a valid bearer).
`tools/call` never bypasses `Runtime.Execute`.

### OpenAPI export

```go
specs := catalog.Build(reg, catalog.ForCapabilities(id.Capabilities))
doc := catalog.OpenAPI("loom", specs, catalog.OpenAPIOptions{ServerURL: "https://api.example"})
// or: GET /v1/openapi.json with Authorization: Bearer …
```

Each op becomes `POST /ops/{name}` with `x-loom-*` governance metadata. Sensitive field **names** never appear.

### App database from env

```bash
export LOOM_APP_DB_URL='postgres://user:pass@localhost/app?sslmode=disable'
export LOOM_APP_DB_DRIVER=pgx          # optional; guessed from URL
export LOOM_APP_DB_POOL=main
export LOOM_APP_DB_TABLES=orders,order_items
export LOOM_APP_DB_BOUNDARIES=prod
```

```go
_ = a.OpenDBFromEnv() // no-op if LOOM_APP_DB_URL unset
```

### InsertReturning

```go
row, err := ex.InsertReturning(ctx, db.InsertOpts{
    Table: "orders",
    Columns: []string{"customer", "sku", "qty", "status", "created_at"},
    Values: []any{...},
    Returning: []string{"id", "customer", "sku"},
})
// Postgres: INSERT … RETURNING; SQLite: insert + last_insert_rowid()
```

## Minimal secure checklist

1. `app.New` — deny by default  
2. `AddUser` with least-privilege capabilities  
3. `GrantOp` / `GrantDBAccess` — explicit allows  
4. Register domain ops or `EnableDBOps`  
5. Every side effect through `a.Call`  
6. Audit sink in production (`AuditSink` or platform file/Postgres)  
7. Multi-tenant data: pool-per-tenant, RLS, or product SQL that always filters by boundary — see [`TENANCY.md`](TENANCY.md)

## What not to do

- Don’t pass `*sql.DB` into request handlers from globals  
- Don’t concatenate user input into SQL  
- Don’t grant `db.query` to product clients if they should only call `order.*`  
- Don’t set `AllowAnonymous: true` in production  
