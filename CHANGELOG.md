# Changelog

All notable changes to Loom are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] — 2026-08-05

### Added

- Structured compliance audit events with execution and trace correlation, operation-version binding, redacted payloads, digests, lifecycle events, and PostgreSQL persistence.
- Metrics for `executed_unconfirmed` outcomes and operational documentation for audit retention, access control, export, and reconciliation.

## [0.1.5] — 2026-08-05

### Fixed

- File-backed execution reconciliation now persists the updated record.
- Failed file-store writes roll back the in-memory mutation and preserve the
  last durable state.
- File and memory execution stores deep-copy caller-visible response maps and
  slices.
- Reconciliation is idempotent for the same outcome and rejects contradictory
  outcomes.

### Added

- PostgreSQL execution-status storage with revision-checked reconciliation.
- PostgreSQL recovery queue claims, leases, release, retention, and archival.
- File-store reload, recovery-queue, concurrent-reconciliation, deep-copy, and
  failed-write tests.
- CI vulnerability, static-analysis, CodeQL, dependency-review, secret-scan,
  container-scan, and SBOM workflows.

## [0.1.4] — 2026-08-05

### Added

- The bounded Loom Schema contract and resource limits.
- Exact operation-version binding across handlers, policies, approvals,
  idempotency, responses, and execution status.
- Execution status, reconciliation, recording-retry APIs, and execution IDs.
- Effect-aware production capability validation and currency allow-lists.
- Signed `MoneyDelta` values and cross-adapter conformance coverage.
- Node.js and Weft SDK usage documentation.

## [0.1.3] — 2026-08-05

### Added

- Exact `core.Money` financial limits and payment-handler arithmetic.
- Bounded input and output schema validation with unsupported-keyword rejection.
- Separate input-field authorization, structured boundary context, and
  execution IDs.
- Explicit `executed_unconfirmed` outcomes and idempotency recording recovery.
- Node.js and Weft SDK process-local clients.
- PostgreSQL tenant isolation support, tenant-bound transactions, an RLS
  reference migration, and cross-tenant adversarial tests.
- Cross-SDK CI for Python, TypeScript, and Rust.

### Changed

- Production construction can require durable security state and explicit
  identity integration.
- Security-sensitive defaults require verified mTLS peers, explicit metrics
  access, generated development credentials, and configured tenant context for
  shared PostgreSQL pools.
- Documentation records the internal two-month use period and open-source
  release context.

## [0.1.2] — 2026-08-05

This release tightened version binding, schema enforcement, output handling,
and production-mode construction. See the repository history for the complete
diff from `0.1.1`.

## [0.1.1] — 2026-08-05

This release added release packaging, tenant claim handling, tenant-bound
PostgreSQL transactions, and stronger production construction checks.

## [0.1.0] — 2026-08-05

Initial public release.

### Added

- Embed-first governance runtime (`app`, `runtime`, policy, guardrails,
  approval, quotas, idempotency, audit).
- Governed database pools, SQL classification, migrations, and `db.query` /
  `db.exec` operations.
- Optional HTTP, MCP, GraphQL, gRPC, CLI, and Weft adapters.
- Agent discovery through `catalog.spec`, OpenAPI, and
  `/.well-known/loom.json`.
- PostgreSQL and Redis durable backends with file and memory development
  fallbacks.
- Cross-platform CLI builds, Dockerfile, installer, Makefile, and release
  workflow.
- Approval claim-before-execution, mTLS peer binding, and production defaults.
- EMBED, SECURITY, TENANCY, BUILD, and installation documentation.

### Notes

- The product version is maintained in the root [`VERSION`](VERSION) file.
- Git tags use the form `vMAJOR.MINOR.PATCH`.
