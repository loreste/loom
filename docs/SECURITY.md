# Security notes

See [`THREAT-MODEL.md`](THREAT-MODEL.md) for trust boundaries, abuse cases,
attacker goals, residual risks, and evidence required before claiming v1.0
production readiness. Report vulnerabilities through the private process in
[`../.github/SECURITY.md`](../.github/SECURITY.md).

## Runtime guarantees

- Decisions default to deny; authentication never implies authorization.
- Authentication, delegation, tenant resolution, boundary membership, policy,
  resource and field access, guardrails, risk, idempotency, approvals, quotas,
  execution status, output filtering, and audit use one governed pipeline.
- Panics and enforcement errors fail closed.
- Approval tokens are stored as hashes and consumed before handlers run.
- Idempotency is scoped by principal, boundary, operation version, and request
  fingerprint.
- Adapter metadata, bypass headers, and body credentials cannot grant access.
- Audit, logs, metrics, and traces redact secrets and use bounded identifiers.
- A side effect whose durable result is uncertain returns
  `executed_unconfirmed`, never a definite failure.

## Durable state and database boundaries

Process-local stores are for development and tests. Production configurations
must provide durable approval, quota, idempotency, execution-status, and audit
state for operations whose effects require them. The SQL guard is defense in
depth, not a database sandbox: use restricted roles, PostgreSQL RLS, tenant-
bound transactions, timeouts, connection limits, and database audit logging.

Application-layer tenant resolution does not replace database isolation. Use
verified tenant claims, `tenancy.NewResolver`, tenant-bound transactions, and
RLS. Keep break-glass access separate, approved, and audited.

## Identity and cryptographic keys

Kubernetes NetworkPolicy defaults to deny-all egress except DNS plus
operator-supplied peers for Postgres, Redis, recovery verifiers, webhooks, and
OIDC. See [`KUBERNETES.md`](KUBERNETES.md).

Audit webhooks, when enabled via `LOOM_WEBHOOK_URL`, attach through bootstrap.
With PostgreSQL and `LOOM_WEBHOOK_DURABLE=true` (default when a database URL is
set), the audit insert and `loom_webhook_outbox` enqueue commit in one
transaction; a worker (`loom webhook-worker`) delivers with lease, retry, and
dead-letter. Production refuses nondurable inline webhooks. Development without
Postgres may use inline best-effort delivery only. Webhooks require HTTPS and a
signing secret in production, reject private/metadata destinations by default,
and never replace PostgreSQL or JSONL durable audit storage. See
[`CONFIGURATION.md`](CONFIGURATION.md).

`identity/oidc` performs configured OIDC discovery, bounded JWKS retrieval,
issuer/audience validation, algorithm allowlisting (with configurable clock
skew on `exp`/`nbf`), key rotation, and explicit claim mapping. The CLI enables
it with `LOOM_OIDC_*` (see [`IDENTITY.md`](IDENTITY.md)). It is not an identity
provider or revocation service. Operators must manage issuer configuration,
provider availability, signing-key rotation, revocation policy, and identity
lifecycle.

Audit checkpoints require a caller-provided signer. Production deployments
should use a KMS/HSM-backed signer, rotate keys under dual control, retain old
verification keys for the full audit-retention period, and preserve key
version metadata with each checkpoint. Never put signing keys in source,
command-line arguments, logs, metrics, or audit events.

## Audit and observability

Use a durable coordinated PostgreSQL audit sink for multi-replica streams and
the process-local `audit.HashChainSink` only for one-writer streams. A hash
chain detects modification but does not make a mutable database immutable;
export verified segments to an access-controlled WORM-capable archive when
required by policy. Metrics and logs support operations but are not the
authoritative security record.
