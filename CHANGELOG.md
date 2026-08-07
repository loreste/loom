# Changelog

All notable changes to Loom are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Embeddable OIDC discovery and JWKS verification with exact issuer and
  audience validation, explicit algorithm allowlists, bounded token and
  upstream response sizes, configurable claim mapping, optional introspection,
  and non-sensitive verifier health counters.
- OIDC adversarial tests covering claim validation, key rotation, tenant
  mismatches, introspection failure, and oversized JWKS responses.
- Recovery workers now support lease heartbeats, bounded scheduled retries,
  attempt tracking, deduplicated escalation, and operator-review dead letters;
  PostgreSQL persists the scheduling state.
- Releases now include checksum manifests, keyless artifact signatures,
  provenance attestations, and an exact-commit CI gate. The installer verifies
  checksums before installation, and all workflow actions are pinned to commit
  SHAs with Dependabot monitoring.
- Added the maintained `observability/otel` bridge for bounded metrics and
  current-span annotations without sensitive or high-cardinality labels.

- Added a maintained recovery-worker CLI with an HTTPS provider-verification
  contract, durable store wiring, and operator-safe execution diagnostics.
- Added authenticated `execution get` and offline `audit verify` CLI commands.
- Added a signed multi-architecture GHCR publication workflow, SDK publication
  workflows with exact version alignment, and release documentation.
- Added a production-oriented Helm chart with separate API/recovery workloads,
  migration hook, probes, PDB, external-secret references, and network policy.
- Added HTTP adapter performance coverage and a metadata-recording benchmark
  runner; durable backend and replica-scale results remain deployment evidence.
- Updated SQLite and Redis dependencies and aligned all CodeQL action components
  to the same major version.

## [0.1.7] — 2026-08-05

### Added

- Official lease-based recovery worker that verifies uncertain external effects,
  retries durable recording, reconciles execution status, and escalates work
  that remains uncertain without rerunning business handlers.
- Tamper-evident audit hash chains, signed checkpoints, verification helpers,
  and PostgreSQL persistence for event hashes, named streams, sequence numbers,
  checkpoint IDs, and shared chain-head locking.
- Performance benchmark and failure-injection evidence with reproducible
  commands and deployment measurement guidance.

### Changed

- Execution creation is immutable: duplicate IDs fail, terminal completion is
  an explicit store transition, and reconciled records cannot move backwards.
- Security checks are blocking gates; container scanning runs on relevant code
  changes, version tags, scheduled scans, and manual runs.
- Go 1.26.5, pgx/v5 5.9.2, x/crypto 0.52.0, and x/text 0.39.0 address the vulnerabilities
  identified by the blocking dependency scan.
- Documentation now covers recovery operations, integrity verification,
  performance measurement, failure injection, and current release behavior.

### Fixed

- PostgreSQL execution inserts can no longer replace an existing execution or
  clear its recovery lease through `Put`.
- File, memory, and PostgreSQL execution stores preserve caller isolation and
  reject unsafe state transitions.

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
