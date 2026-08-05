# Loom Universal Runtime

**Build secure apps without an API surface.**  
Loom is an **in-process execution-governance runtime**: identity, authorization, SQL/database guardrails, approvals, quotas, idempotency, and audit wrap every operation. HTTP, MCP, and Weft are **optional edges** — not required to use Loom.

> Never trust the caller. Never trust the model. Always trust verified identity, policy, and runtime enforcement.  
> **Default: DENY.**

## What problem this solves

Teams want to ship product logic (including **database access**) without standing up a custom authz API for every feature. Loom lets you:

1. **Embed** a runtime in your Go process  
2. **Register** named DB pools (DSN locked inside Loom)  
3. **Call** operations (`db.query`, `db.exec`, or your own) through one pipeline  
4. Optionally expose the *same* runtime over HTTP later — same security path  

```
Your code  →  app.Call / Runtime.Execute  →  Handler / DB executor
                    ↑
     identity · policy · guardrails · risk · approval · quotas · audit
```

## Quick start (no HTTP)

```bash
go test -race ./...
go run ./examples/embed/         # governed SQL ops
go run ./examples/orders-app/    # product ops; callers never send SQL
go run ./examples/worker/        # job queue → Loom (no HTTP)
go run ./examples/agent-client/  # manifest → openapi → MCP → execute
```

### Install / cross-compile (Windows · macOS · Linux)

```bash
# Native binary
make build          # → bin/loom

# All platforms (CGO-free)
make release        # → dist/loom-<ver>-{linux,darwin,windows}-{amd64,arm64}[ .exe]
# or: ./scripts/build-release.sh

./dist/loom-*-$(go env GOOS)-$(go env GOARCH) version
```

| Platform | Arch |
|----------|------|
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |
| Windows | amd64, arm64 |

Binaries are pure Go (`CGO_ENABLED=0`). Checksums land in `dist/SHA256SUMS`.  
Tag `v*` triggers the GitHub Release workflow (`.github/workflows/release.yml`).

Deep dive: [`docs/EMBED.md`](docs/EMBED.md)

### App DB + jobs

```bash
export LOOM_APP_DB_URL='file:app.db'
export LOOM_APP_DB_DRIVER=sqlite
export LOOM_APP_DB_TABLES=orders
```

```go
a.OpenDBFromEnv()
// jobs always go through Call — never a privilege path
runner := &job.Runner{Queue: q, Caller: a, Token: svcToken}
```

Minimal pattern:

```go
a, _ := app.New(app.Config{})
defer a.Close()

// Connect DB — credentials stay inside the registry
a.DBs.RegisterDB("main", sqldb, db.Options{
    AllowedTables:     []string{"orders"},
    AllowedBoundaries: []core.BoundaryID{"dev"},
})
a.EnableDBOps()

// Least privilege (everything else is denied)
a.AddUser("user:svc", token, "dev", []string{"db.query", "db.exec"})
a.AllowPolicy(policy.Rule{Principal: "user:svc", Boundary: "dev", Operation: "db.query", Priority: 10})
// ... resource + field grants ...

// All data access through Loom
resp := a.Call(ctx, core.Request{
    Operation:   "db.query",
    Credentials: core.Credentials{Token: token},
    Boundary:    "dev",
    Resource:    &core.ResourceRef{Type: "db", ID: "main"},
    Input: map[string]any{
        "pool": "main",
        "sql":  "SELECT id, total FROM orders WHERE id = ?",
        "args": []any{42},
    },
})
```

## Secure database connectivity

| Control | Behavior |
|---------|----------|
| Named pools | `Open` / `RegisterDB` — DSN not retained on the handle |
| No raw `*sql.DB` to callers | `db.Executor` only (or governed ops) |
| SQL class guard | Single statement; no comments; no multi-stmt; blocks `pg_sleep`, `COPY`, DDL, etc. |
| Read vs write | `db.query` → SELECT/WITH; `db.exec` → INSERT/UPDATE/DELETE |
| Table allowlist | Optional per pool (`AllowedTables`) |
| Boundary pin | Optional `AllowedBoundaries` |
| Max rows / args / timeout | Hard caps |
| Loom policy still applies | Capability + allow rule + resource ACL + field filter + audit |

**Postgres example:**

```go
import _ "github.com/jackc/pgx/v5/stdlib"

a.OpenDB("primary", "pgx", os.Getenv("DATABASE_URL"), db.Options{
    AllowedTables:     []string{"public.accounts", "public.ledger"},
    AllowedBoundaries: []core.BoundaryID{"prod"},
    StatementTimeout:  5 * time.Second,
    MaxRows:           500,
})
```

Writes (`db.exec`) are **high risk** → approval + idempotency by default.

## Package map

| Package | Role |
|---------|------|
| **`app`** | Embed Loom without servers |
| **`db`** | Secure pools, SQL guard, `db.query` / `db.exec` |
| `runtime` | Permission pipeline |
| `policy` / `identity` / `boundary` / … | Enforcement building blocks |
| `adapters/*` | Optional HTTP / CLI / MCP / GraphQL / gRPC / Weft |
| `sdk/*` | Optional remote clients (still server-enforced) |

## Optional: HTTP later

When you need a network edge, the **same** runtime serves:

```bash
go run ./cmd/loom serve --addr=:8080 --grpc-addr=:9090 --database-url=... --redis-url=...
```

HTTP: `/v1/execute`, `/mcp`, `/graphql`, discovery.  
gRPC: `loom.v1.Runtime/Execute` (optional `--grpc-addr` / `LOOM_GRPC_ADDR`).

Remote SDKs only call the governed edge — they cannot grant power locally.

Production: set `LOOM_ENV=production`, `LOOM_DISABLE_DEMO_PRINCIPALS=true`,
`LOOM_REQUIRE_DURABLE=true`, and a real `LOOM_JWT_SECRET`. See [`docs/SECURITY.md`](docs/SECURITY.md).

## Security posture

- Default **deny**; explicit grants only  
- Adapter headers like `X-Loom-Bypass` hard-denied  
- Fail-closed on policy/SQL/guardrail errors  
- Secrets redacted in audit; sensitive fields need explicit field grants  
- Redis quotas fail-closed when configured  

## Demo principals (CLI platform)

| Principal | Token | Notes |
|-----------|-------|--------|
| `user:alice` | `alice-secret-token` | documents / AI |
| `user:bob` | `bob-finance-token` | payments |
| `user:approver` | `approver-admin-token` | approvals / policy |

For **embed** apps, you define your own users with `AddUser` — nothing is open by default.

## License

Apache-2.0 (or as designated by the project owner).
