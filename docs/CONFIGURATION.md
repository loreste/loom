# Configuration reference

The CLI reads process configuration from `LOOM_*` environment variables.
Command-line flags take precedence for the server settings they expose. An
embedded application can provide the equivalent values directly through
`app.Config` and `bootstrap.Config`.

## Server and storage

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOOM_ADDR` | `:8080` | HTTP listen address. |
| `LOOM_DATA_DIR` | empty | Directory for single-node file-backed approval, idempotency, execution, and audit state. |
| `LOOM_DATABASE_URL` | empty | PostgreSQL DSN for shared durable Loom metadata and execution state. |
| `LOOM_REDIS_URL` | empty | Redis URL for shared quota state. |
| `LOOM_PG_MAX_OPEN` | `20` | PostgreSQL maximum open connections. |
| `LOOM_PG_MAX_IDLE` | `5` | PostgreSQL maximum idle connections. |
| `LOOM_AUDIT_JSONL` | empty | Optional JSONL audit sink path. |

Storage precedence is PostgreSQL, then `LOOM_DATA_DIR`, then memory when the
deployment is not requiring durable state. Production-like configuration must
choose durable storage explicitly.

## Environment and production controls

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOOM_ENV` | `development` | Runtime profile. `production`, `prod`, and `staging` use production-like validation. |
| `LOOM_REQUIRE_DURABLE` | `false` | Refuses startup when required state would be process-local. |
| `LOOM_DISABLE_DEMO_PRINCIPALS` | `false` | Prevents development demo principals from being seeded. Required with durable CLI bootstrap. |
| `LOOM_ALLOW_DEMO` | `false` | Configuration validation escape for controlled non-production use; durable CLI bootstrap still requires demo principals to be disabled. |
| `LOOM_QUOTA_FAIL_CLOSED` | `true` | Denies when a configured Redis quota backend cannot be evaluated. |
| `LOOM_HTTP_RATE_LIMIT` | `0` | Per-client-IP HTTP request limit per minute; `0` disables the edge limiter. |
| `LOOM_TRUSTED_TLS_PROXY` | `false` | Declares that a trusted deployment terminates TLS before Loom. Required before a production plaintext listener is allowed. |

When `LOOM_ENV` is production-like, Loom requires an injected or configured
identity verifier, non-demo principals, durable state, a JWT secret, issuer,
and audience. With `LOOM_REQUIRE_DURABLE=true`, the CLI also requires a
PostgreSQL or file data directory, Redis, and a JWT secret.

## JWT and tenant settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOOM_JWT_SECRET` | generated for development | HMAC verification secret. Minimum length and production validation apply. |
| `LOOM_JWT_KEY_ID` | empty | Key ID used by the configured JWT verifier. |
| `LOOM_JWT_ISSUER` | empty | Expected JWT issuer. Required in production-like profiles. |
| `LOOM_JWT_AUDIENCE` | empty | Expected JWT audience. Required in production-like profiles. |
| `LOOM_TENANT_CLAIM` | empty | Verified JWT claim copied to Loom's `tenant_id` attribute. |

The built-in HMAC verifier is intended for controlled deployments and tests.
Embed `identity/oidc` for OIDC discovery and JWKS rotation, and configure its
issuer, audience, algorithm allowlist, response limits, and claim mappings
explicitly. See [`IDENTITY.md`](IDENTITY.md) for the production requirements.

## Policy synchronization

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOOM_POLICY_PATH` | empty | Policy document path used by the policy source. |
| `LOOM_POLICY_SYNC_INTERVAL` | `5s` | Poll interval for policy synchronization. |

Policy reload failures fail closed and should be monitored.

## Compliance audit configuration

`LOOM_AUDIT_JSONL` enables a JSON Lines audit sink for single-node deployments or log shippers. The path must be owned by the service account, have restrictive permissions, and be included in the backup and retention plan. A plain file is not an immutable archive.

When `LOOM_DATABASE_URL` is configured, the PostgreSQL bootstrap includes the structured `loom_audit` table and indexes for execution, trace, principal, tenant, operation, decision, and reason. Use PostgreSQL permissions to separate audit writers from audit readers, and export records to an append-only or WORM-capable system when required.

Audit records contain redacted input, metadata, and scrubbed operational notes. They include SHA-256 digests for correlation instead of raw credentials, approval tokens, idempotency keys, SQL, or unrestricted request bodies. Do not add those values to application log fields, metric labels, or tracing attributes.

The runtime emits one `execution.decision` record per attempt and lifecycle records for reconciliation and recovery queue operations. Use `execution_id` and `trace_id` to correlate records across adapters and services. See [`OBSERVABILITY.md`](OBSERVABILITY.md) for event fields, dashboards, retention, and incident handling.

## Development demo tokens

The CLI accepts these values only for seeded development principals:

| Variable | Principal |
| --- | --- |
| `LOOM_DEMO_TOKEN_ALICE` | `user:alice` |
| `LOOM_DEMO_TOKEN_BOB` | `user:bob` |
| `LOOM_DEMO_TOKEN_OPS` | `user:ops` |
| `LOOM_DEMO_TOKEN_APPROVER` | `user:approver` |
| `LOOM_DEMO_TOKEN_AGENT` | `agent:assistant` |

If a value is omitted, the bootstrap generates a process-local development
token. The generated value is not a production credential and is not intended
to be recovered after restart.

## Application database settings

These variables configure an application's own governed database pool. They
are separate from `LOOM_DATABASE_URL`, which configures Loom's metadata stores.

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOOM_APP_DB_URL` | empty | Application PostgreSQL or SQLite URL. Empty means not configured. |
| `LOOM_APP_DB_DRIVER` | inferred | `pgx`/`postgres` for PostgreSQL or `sqlite` for SQLite. |
| `LOOM_APP_DB_POOL` | `main` | Registered pool name. |
| `LOOM_APP_DB_TABLES` | empty | Comma-separated SQL table allowlist. |
| `LOOM_APP_DB_BOUNDARIES` | empty | Comma-separated allowed application boundaries. |
| `LOOM_APP_DB_READONLY` | `false` | Opens the application pool read-only where supported. |
| `LOOM_APP_DB_MAX_ROWS` | `1000` | Maximum rows returned by governed queries. |
| `LOOM_APP_DB_TIMEOUT` | `5s` | Statement timeout. |
| `LOOM_APP_DB_REQUIRE_TENANT_RLS` | `false` | Requires tenant-bound transactions for PostgreSQL. |
| `LOOM_APP_DB_TENANT_SETTING` | empty | PostgreSQL transaction-local setting used by RLS policies. |

An application database pool is still subject to operation policy, resource
authorization, SQL classification, and tenant controls.

## CLI flags

The `serve` command accepts these deployment overrides:

```text
loom serve
  --addr=:8080
  --grpc-addr=:9090
  --data-dir=./data
  --database-url=postgres://...
  --redis-url=redis://...
  --tls-cert=/path/server.crt
  --tls-key=/path/server.key
  --client-ca=/path/clients.ca
```

Use `loom help` for the current command list. Use `loom version` to see the
binary version and build metadata.

## Recovery worker settings

`loom recovery-worker` requires an application-owned HTTPS verifier URL; HTTP is permitted only for localhost during development. The command accepts equivalent flags, while these environment variables are convenient in deployment manifests:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOOM_RECOVERY_VERIFIER_URL` | empty | Required provider-verification endpoint; HTTPS is required outside localhost. |
| `LOOM_RECOVERY_VERIFIER_TOKEN` | empty | Optional bearer token for the verifier endpoint. |
| `LOOM_RECOVERY_OWNER` | `loom-recovery-worker` | Unique worker owner name. |
| `LOOM_RECOVERY_LEASE` | `5m` | Lease duration. |
| `LOOM_RECOVERY_POLL` | `5s` | Queue polling interval. |
| `LOOM_RECOVERY_BACKOFF_BASE` | `1s` | Initial retry backoff. |
| `LOOM_RECOVERY_BACKOFF_MAX` | `5m` | Maximum retry backoff. |
| `LOOM_RECOVERY_MAX_ATTEMPTS` | `8` | Automatic attempts before operator review. |

The verifier must perform an authoritative provider lookup and must not trust a caller-supplied success flag. The recovery worker never invokes the original business handler. See [`RECOVERY.md`](RECOVERY.md).
