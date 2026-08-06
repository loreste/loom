# Embedding Loom

Loom does not require an API server. The primary integration is an `app.App`
embedded in a Go process. HTTP, MCP, GraphQL, gRPC, CLI, and Weft are optional
edges over the same runtime.

## Product operations

Register domain operations and keep SQL inside governed handlers:

```text
client or worker
    → app.Call
        → identity and policy gates
        → handler using a governed Executor
        → database
```

Callers should not receive raw database handles or construct SQL from request
input. See `examples/orders-app/` and `domains/orders/`.

## Minimal embedded construction

```go
a, err := app.New(app.Config{})
if err != nil {
    return err
}

if err := a.Register(operation, handler); err != nil {
    return err
}

response := a.Call(ctx, core.Request{
    Operation:   "order.create",
    Credentials: core.Credentials{Scheme: "bearer", Token: token},
    Boundary:    "dev",
    Input:       map[string]any{"sku": "SKU-1"},
})
```

Grant the principal, operation policy, resource access, and field access
explicitly. A zero-value or missing rule does not allow the request.

## Governed SQL operations

Administrative or controlled tooling can use `db.query` or `db.exec` when all
of these are configured:

- the capability is granted explicitly;
- policy and resource access allow the pool;
- the SQL guard accepts the statement; and
- the pool table allowlist contains every referenced table.

Prefer fixed domain operations for product callers.

## Database registration

| Database | Import | `OpenDB` driver |
| --- | --- | --- |
| PostgreSQL | `_ "github.com/jackc/pgx/v5/stdlib"` | `pgx` |
| SQLite | `_ "modernc.org/sqlite"` | `sqlite` |

```go
_ = a.OpenDB("primary", "pgx", os.Getenv("DATABASE_URL"), db.Options{
    AllowedTables:     []string{"public.orders", "public.order_items"},
    StatementTimeout:  5 * time.Second,
    MaxRows:           500,
    ReadOnly:          false,
})
```

Run migrations at startup before registering the application SQL path. DDL is
blocked in the governed request path by design:

```go
mig := db.NewMigrator(sqldb, db.DialectPostgres)
if err := mig.Apply(ctx, migrations); err != nil {
    return err
}
```

Use `?` placeholders in application SQL; Loom rebinds them for PostgreSQL.

## One-shot bootstrap

`app.Bootstrap` can migrate a configured application database, register domain
operations, and seed least-privilege development users. See the complete
example in `examples/orders-app/main.go` and the environment-driven database
settings in the source comments for `app.OpenDBFromEnv`.

## Background jobs

Use `job.Runner` with an in-memory, SQLite, or PostgreSQL queue. Queue delivery
is not a privilege path; every job becomes an `app.Call` and passes the full
pipeline. Approval tokens are not persisted by the job queue.

## Optional network edges

| Edge | Path or API | Notes |
| --- | --- | --- |
| HTTP | `POST /v1/execute` | Primary remote surface |
| MCP | `POST /mcp` | JSON-RPC `tools/list` and `tools/call` |
| GraphQL | `POST /graphql` | `execute` mutation |
| gRPC | `loom.v1.Runtime/Execute` | Proto under `adapters/grpc/proto` |
| Weft | in-process | Workflow step adapter |

None of these edges can bypass `Runtime.Execute`.

## Discovery

The HTTP adapter provides:

1. `GET /.well-known/loom.json` for static service discovery;
2. `GET /v1/openapi.json` for capability-filtered OpenAPI; and
3. `catalog.spec` through the execution path for governed operation metadata.

OpenAPI and MCP descriptions are projections of the caller's capabilities.
They are not authorization decisions and can change when policy changes.

## Production embedded construction

Use `Environment: "production"` with an injected identity verifier and durable
implementations appropriate to the registered operation effects. Set
`RequireDurableSecurityState: true` when startup must reject process-local
security stores. `app.New` does not silently replace production dependencies
with memory implementations.

For a multi-node deployment, use the PostgreSQL bundle for approvals,
idempotency, execution status, and audit, and Redis for shared quotas where
needed. See [`INSTALL.md`](INSTALL.md), [`IDENTITY.md`](IDENTITY.md), and
[`COMPATIBILITY.md`](COMPATIBILITY.md).

## Secure embedding checklist

1. Construct an app with deny-by-default behavior.
2. Inject a production identity verifier.
3. Register operations with exact versions and bounded schemas.
4. Grant least-privilege policy, resource, and field access.
5. Use governed database executors and tenant-bound transactions.
6. Require idempotency and durable execution status for side effects.
7. Configure approval and audit storage for high-risk operations.
8. Protect operational endpoints and export safe metrics.
9. Add adversarial tests for every new control.

## Avoid

- passing a raw `*sql.DB` into request handlers;
- concatenating user input into SQL;
- granting `db.query` to callers that only need a domain operation;
- trusting caller-supplied tenant or identity metadata; or
- enabling anonymous access or demo principals in production.
