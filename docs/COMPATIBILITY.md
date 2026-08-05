# Compatibility contracts

Loom adapters and SDKs share one execution contract. The current major
protocol version is exposed as `X-Loom-Protocol-Version: 1` on HTTP responses;
clients should record and alert on an unexpected version instead of guessing.

The following rules apply within protocol version 1:

- Response fields may be added, but existing field meaning and JSON types do
  not change.
- Denial reason codes are stable machine-readable identifiers. New codes are
  additive; callers must treat unknown codes as `internal`/deny.
- Operation names, input schemas, output field grants, risk, approval, and
  idempotency requirements are versioned application policy, not SDK defaults.
- SDKs send the protocol header and must preserve unknown response fields.
- OpenAPI and MCP documents are capability-filtered projections. They are not
  authorization decisions and may change when policy changes.
- Policy documents use monotonically increasing versions. A node must reject a
  stale or newer-than-supported document rather than silently applying it.
- Database migrations must be forward-compatible with the running binary;
  PostgreSQL schema version checks refuse silent downgrade.

Breaking changes require a new protocol major, a migration note, compatibility
tests for every maintained SDK, and a documented deprecation window. The
`sdk-contract-server` fixture and SDK CI jobs exercise the same operation across
Go, Python, TypeScript, and Rust.
