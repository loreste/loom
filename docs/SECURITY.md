# Security notes

Loom has been used internally for roughly two months and is now being published as open source. This document describes controls present in the repository and the responsibilities that remain with the deploying application.

## Runtime guarantees

- Decisions default to deny.
- Authentication, delegation, tenant resolution, boundary membership, policy, resource access, input/output field authorization, guardrails, risk, idempotency, approvals, quotas, execution status, output filtering, and audit are part of one pipeline.
- Panics and enforcement errors fail closed.
- Approval tokens are stored as hashes and consumed before the handler runs.
- Idempotency keys are scoped by principal, boundary, operation, selected operation version, and request fingerprint.
- Caller-supplied bypass headers, body credentials, and adapter metadata do not grant privilege.
- Audit input and metadata are redacted recursively; opaque secrets such as idempotency keys are represented by digests.
- SQL rejects multi-statements, comments, DDL/admin statements, dangerous functions, and tables outside the configured allowlist.
- Financial amounts use exact `core.Money` values rather than `float64`.
- Declared input and output schemas use bounded Loom Schema validation; unsupported schema keywords fail closed.
- Output is filtered and redacted before it is returned to the caller.
- A side effect whose post-execution recording cannot be confirmed returns `executed_unconfirmed` with an execution ID rather than pretending the operation was an ordinary denial.

## Durable state

Process-local stores are useful for development and tests. Production mode requires durable approval, quota, idempotency, execution-status, and audit components when registered operations need them.

- File-backed state is suitable for one node and survives process restart; it is not a multi-node coordination system.
- PostgreSQL stores provide shared approval, audit, idempotency, policy, and execution-status state.
- Redis provides shared quota state when configured.
- Recovery workers claim leases and record completion; they never rerun the business handler.

Configure durability based on the effects of registered operations. A read-only process may not need every stateful control, while a payment or provisioning operation needs the complete durable path.

## Database boundaries

The SQL guard is defense in depth, not a parser-grade database sandbox. Use restricted database roles, read-only credentials where appropriate, PostgreSQL RLS for shared tenant tables, tenant-bound transactions, statement timeouts, connection limits, and database-level audit logging. Never pass a raw `*sql.DB` into an application handler; use Loom's governed database registry and executor.

## Identity boundaries

Loom authenticates credentials but does not provide OIDC discovery, JWKS rotation, revocation, or enterprise identity lifecycle management. Inject an application verifier and configure issuer, audience, algorithms, key rotation, certificate rotation, claim mapping, and revocation behavior. The built-in HMAC verifier is intended for controlled deployments and tests. Demo principals are development credentials, not production identities.

See [`IDENTITY.md`](IDENTITY.md).

## Tamper-evident compliance records

Configure a durable audit sink and use `audit.NewHashChainSink` when the
deployment needs evidence of modification. Create signed checkpoints with a
caller-managed key, export events and checkpoints to an immutable destination,
and verify them before compliance reports or retention cleanup. The hash chain
detects changes; it does not make a mutable database immutable by itself.

## Tenant boundaries

Application-layer tenant resolution does not replace database isolation. Use verified tenant claims, `tenancy.NewResolver`, tenant-bound PostgreSQL transactions, and RLS for shared tables. Keep break-glass access separate, approved, and audited.

See [`TENANCY.md`](TENANCY.md).

## Network adapter boundaries

HTTP, MCP, GraphQL, gRPC, CLI, Weft, and worker paths are untrusted adapter boundaries. They must translate into the same runtime entry point. Do not add header or request-body bypasses. Protect `/metrics`, `/readyz`, execution status, reconciliation, and discovery surfaces according to their documented authentication requirements. Do not expose development configuration or demo credentials on a public network.

## Compliance logging boundary

Loom provides structured decision and execution-lifecycle events with stable correlation IDs, operation versions, enforcement stages, outcomes, redacted fields, and payload digests. This supports review and incident correlation without turning the audit sink into a second unrestricted request-data store.

Configure durable audit storage for production. PostgreSQL and file-backed sinks still require deployment controls for encryption, access, backups, retention, tamper evidence, and archival. Export to an immutable archive when regulation or internal policy requires it. Audit failure on an allow path is surfaced as an uncertain outcome because the handler may already have caused a side effect; reconciliation APIs are part of recovery.

Metrics and application logs are supporting telemetry, not the authoritative security record. Do not put raw credentials, approval tokens, idempotency keys, SQL, request bodies, secret fields, or high-cardinality identifiers in logs, metrics, traces, or labels.

See [`OBSERVABILITY.md`](OBSERVABILITY.md).

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. Use the repository's private security contact, include reproduction steps and impact, and avoid sending real credentials or customer data.
