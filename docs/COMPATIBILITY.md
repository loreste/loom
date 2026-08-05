# Compatibility contracts

Loom adapters and SDKs share one execution contract. The current protocol
version is `1`, exposed as `X-Loom-Protocol-Version: 1` on HTTP responses.

## Operation versions and execution outcomes

Every registered operation has an exact `Version`; the default is `"1"`.
Requests select it with `operation_version`. An unknown or mismatched version
is denied, and idempotency storage keys include the selected version. Every
execution response returns the selected `OperationVersion` when a contract
was resolved; unknown operations return the normalized requested version.

`executed_unconfirmed` means the handler may have run but post-execution
recording could not be confirmed. Callers must query the execution record and
reconcile it before retrying a side-effecting operation. `retry_recording`
requeues recording work only; it never reruns the handler.

## Compatibility rules

The following rules apply within protocol version 1:

- Response fields may be added, but existing field meanings and JSON types do
  not change.
- Denial reason codes are stable machine-readable identifiers. New codes are
  additive; callers must treat unknown codes as internal denial.
- Operation names, schemas, field grants, risk, approval, idempotency, and
  currency requirements are versioned application policy, not SDK defaults.
- SDKs send the protocol header and preserve unknown response fields.
- OpenAPI and MCP documents are capability-filtered projections, not
  authorization decisions; policy changes may change their contents.
- Policy documents use monotonically increasing versions. Nodes reject stale
  or newer-than-supported documents rather than silently applying them.
- Database migrations are forward-compatible with the running binary;
  PostgreSQL schema checks refuse silent downgrade.

Breaking changes require a new protocol major, a migration note, compatibility
tests for every maintained SDK, and a documented deprecation window.

The `sdk-contract-server` fixture and SDK CI jobs exercise the same operation
across Go, Python, TypeScript, and Rust. Adapter conformance tests cover the
native, HTTP, MCP, GraphQL, gRPC, CLI, and Weft paths and compare the selected operation version,
decision, filtered output, and execution outcome.
