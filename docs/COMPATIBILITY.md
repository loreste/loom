# Compatibility contracts

Loom adapters and SDKs share protocol version `1`, exposed by HTTP responses as
`X-Loom-Protocol-Version: 1`. Protocol version is separate from the Loom
release version in [`VERSION`](../VERSION).

## Operation versions and outcomes

Every registered operation has an exact `Version`. An empty request version
selects the registry's default operation version; a supplied version must
match exactly. The selected version is returned in the execution response and
is included in idempotency fingerprints, approval binding, execution records,
and policy evaluation. An unknown operation or version is denied.

`executed_unconfirmed` means the handler may have run but durable
post-execution recording was not confirmed. Callers must query the execution
record and reconcile the external result before retrying a side-effecting
operation. Recording recovery never reruns the handler.

## Recovery compatibility

Recovery status fields are additive within protocol version 1. Clients must
preserve unknown execution states and fields. PostgreSQL may expose
`recovery_attempt`, `next_attempt_at`, bounded failure summaries,
`recovery_escalated`, and the `operator_review` state without changing the
meaning of existing allowed, denied, or reconciled outcomes.

`operator_review` is a dead-letter state. A worker cannot move it backward; an
approved administrative operation must explicitly requeue it. Durable
deployments may expose governed `recovery.list`, `recovery.requeue`, and
`recovery.dead_letter` operations when the execution store supports the
recovery-admin interface. Requeue and dead-letter transitions require explicit
policy grants, approval, idempotency, and lease/state guards; no control-plane
client may mutate recovery rows directly. Lease renewal is
guarded by execution ID and lease ID, so a stale worker cannot extend or
complete another worker's claim.

## Rules within protocol version 1

- Response fields may be added, but existing field meanings and JSON types do
  not change.
- Denial reason codes are stable machine-readable identifiers. New codes are
  additive; changing the meaning of an existing code requires a new protocol
  version.
- Operation names, schemas, field grants, risk, approval, idempotency, quota,
  and recovery policy bind to the selected operation version.
- SDKs send the protocol header and preserve response fields they do not use.
- OpenAPI and MCP documents are capability-filtered projections, not
  authorization decisions; their contents may change when policy changes.
- Policy documents use monotonically increasing versions. A node rejects stale
  or unsupported policy documents instead of applying them silently.
- PostgreSQL migrations are forward-only for a running binary. Schema version
  checks refuse silent downgrade.

Breaking changes require a new protocol major, a migration note, compatibility
tests for each maintained SDK, and a documented deprecation window.

## Audit event schema

Audit events have their own `schema_version`, independent of Loom protocol and
operation versions. Consumers must preserve unknown fields and branch only on
documented stable fields such as `event_type`, `decision`, `outcome`, and
`step`. Removals or semantic changes require a new audit schema version.

## Conformance coverage

The repository's adapter conformance tests compare native, HTTP, MCP,
GraphQL, gRPC, CLI, and Weft paths. SDK contract tests exercise the same
operation through Go, Python, TypeScript, and Rust clients and compare
identity, boundary, operation version, decision, filtered output, outcome, and
audit metadata.
