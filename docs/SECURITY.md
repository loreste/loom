# Loom security notes

Loom has been used internally for the past two months and is now being
reviewed as an open-source project. This document describes the controls in
the current repository and the responsibilities that remain with a deploying
application.

## Runtime guarantees

- Decisions default to deny.
- Authentication, delegation, tenant resolution, boundary membership, policy,
  resources, guardrails, risk, idempotency, approvals, quotas, execution,
  output filtering, and audit all run through one pipeline.
- Enforcement errors and panics fail closed.
- Approval tokens are hashed and consumed before handlers run.
- Idempotency state is scoped by principal, boundary, operation, and key.
- Caller-supplied bypass headers and body credentials do not grant privilege.
- Audit input is recursively redacted by value and sensitive field name.
- SQL rejects multi-statements, comments, DDL/admin statements, dangerous
  constructs, and unallowlisted function calls. It is not a parser-grade
  database sandbox.
- Tenant-aware pools can require a PostgreSQL transaction-local RLS setting;
  direct pooled queries and tenant-setting mutation are refused.

## Transport requirements

The HTTP adapter only treats a client certificate as mTLS identity when the
TLS connection has a verified chain. A fingerprint or presented certificate is
not sufficient.

Production-like CLI serving requires TLS certificates for direct HTTP and gRPC
listeners. TLS termination by a trusted proxy must be explicitly configured
with `LOOM_TRUSTED_TLS_PROXY=true`; that proxy and its network boundary remain
deployment responsibilities.

Metrics are protected by an explicit authorizer or must be deliberately marked
public. Health endpoints are intentionally separate from authenticated
operations.

## Identity responsibilities

Loom authenticates credentials; it is not an identity provider. Production
deployments should provide an OIDC/JWKS-backed verifier or another managed
verifier with:

- issuer and audience validation;
- bounded key caching and rotation behavior;
- algorithm and expiry restrictions;
- explicit subject, service, and tenant claim mapping; and
- a documented revocation strategy.

The built-in HMAC and static verifiers are for controlled deployments,
development, and tests. Development demo credentials are generated at startup
or supplied explicitly through environment configuration. They are not
production identity.

## Tenancy responsibilities

Configure `tenancy.NewResolver` when a verified tenant claim must match the
request boundary. For shared PostgreSQL tables, use `RequireTenantContext`,
`BeginTenant`/`BeginScoped`, RLS, a non-owner role, and `FORCE ROW LEVEL
SECURITY`. Loom boundary policy is not a substitute for database isolation.
See [`TENANCY.md`](TENANCY.md) and the [tenant reference](../examples/tenancy/README.md).

## Production checklist

```bash
export LOOM_ENV=production
export LOOM_DISABLE_DEMO_PRINCIPALS=true
export LOOM_REQUIRE_DURABLE=true
export LOOM_DATABASE_URL='postgres://managed-user@db/loom'
export LOOM_REDIS_URL='redis://managed-redis/0'
export LOOM_JWT_SECRET="$(openssl rand -hex 32)" # use your secret manager in production
export LOOM_JWT_ISSUER='https://issuer.example'
export LOOM_JWT_AUDIENCE='loom-api'
export LOOM_TENANT_CLAIM=tenant_id # only for tenant-aware deployments
# Either provide --tls-cert/--tls-key, or explicitly run behind a trusted TLS proxy.
```

Also use restricted database roles, RLS for shared tenant tables, statement
timeouts, connection limits, network egress controls, and an operational audit
sink. File-backed state is durable for a single node; it is not a distributed
approval or idempotency store.

## Verification

Run:

```bash
go vet ./...
go test -race ./...
go test -fuzz=FuzzExecute -fuzztime=15s ./runtime/
```

The CI workflow also runs SDK tests and cross-SDK contract tests. Dependency
and static security scanners should be installed in CI where the runner
environment permits them.
