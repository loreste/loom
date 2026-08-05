# Loom — agent notes

## Product intent

Loom is an **embed-first** governance runtime so teams can **build without a custom authz API**, including **secure DB access**. HTTP/MCP/Weft are optional adapters.

Primary path: `app.App` → `Call` → pipeline → handlers / `db.Executor`.

## Non-negotiables

1. **Default DENY.** Zero-value decisions, missing rules, and eval errors are deny.
2. **Fail closed.** Panics in guardrails, audit misconfig on emit path, filter errors → no data leak.
3. **Single entrypoint.** Business logic runs only via `runtime.Runtime.Execute` / `app.Call`. Adapters never call handlers directly.
4. **No adapter privilege.** Headers like `X-Loom-Bypass` / `X-Admin-Override` are hard-denied in policy.
5. **Core stays free of MCP/Weft.** Adapters import runtime; runtime never imports adapters.
6. **Secrets never in audit raw.** Use redaction helpers.
7. **No raw `*sql.DB` to app callers.** Use `db` registry + SQL classify; DSN not retained after open.
8. **SQL fail-closed.** Multi-statement, comments, DDL/admin, danger functions → reject.

## Package map

| Package | Trust role |
|---------|------------|
| `core` | Types only |
| `identity` | Mints `Identity` |
| `boundary` | Tenant isolation |
| `policy` | Allow rules (explicit) |
| `resource` | Resource + field ACL |
| `guardrails` | Hard safety |
| `catalog` | Agent-facing tool specs + discovery manifest (metadata only) |
| `risk` / `approval` / `quotas` / `idempotency` | Pre-exec gates |
| `audit` | Observability |
| `runtime` | Pipeline owner |
| `app` | Embed API (`New` / `Bootstrap` / `Call`); no server required |
| `job` | Queue → `Call` (memory or SQL); not a privilege path |
| `adapters/*` | Untrusted edge (HTTP / CLI / MCP / GraphQL / gRPC / Weft) |

## Storage precedence

Durable: `DatabaseURL` (Postgres) → `DataDir` (files) → memory.  
Quotas: `RedisURL` → memory. Redis errors **fail closed** by default.

Postgres package: `store/postgres`. Never store raw approval tokens (hash only).  
Quotas package: shared `quotas.Config`; Redis uses atomic Lua INCR + rollback on exceed.

Approval: `Evaluate` checks; `Consume` claims **before** the handler (single-use burn).  
mTLS: only `CredentialsFromCertificate` (TLS peer) authenticates — fingerprint alone is not enough.  
Production: `LOOM_ENV=production` requires durable stores, no demo principals, real JWT secret.  
Security notes: [`docs/SECURITY.md`](docs/SECURITY.md).

## Testing

```bash
go test -race ./...
go test -fuzz=FuzzExecute -fuzztime=10s ./runtime/

# Optional integration (requires LOOM_DATABASE_URL)
export LOOM_DATABASE_URL='postgres://loom:loom@127.0.0.1:5432/loom?sslmode=disable'
go test ./store/postgres/ ./bootstrap/ -run Postgres -count=1
```

When adding features: write an adversarial test that tries to bypass the new control.
