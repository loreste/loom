# Changelog

All notable changes to Loom are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — 2026-08-09

### Added

- **Webhook notifications** (`webhook/`): `audit.Sink` that delivers events to
  HTTP endpoints with HMAC-SHA256 signing, configurable filtering, and
  fail-open or fail-closed delivery modes.
- **Pipeline tracing** (`runtime.Tracer`): per-stage span events through the
  execution pipeline. The `observability/otel` bridge implements both
  `Observer` and `Tracer`; zero overhead when nil.
- **Declarative policy** (`policy.LoadFile`, `policy.LoadInto`): JSON file
  loader for policy rules with atomic replacement and round-trip serialization.
- CLI policy management: `loom policy lint`, `test`, `diff`, `explain`,
  `simulate` for operator-safe policy inspection and validation.
- Recovery administration: `loom recovery list`, `approve`, `reject`,
  `dead-letter` with authenticated access control.
- Operator CLI: `loom operator status`, `metrics`, `config` for operational
  visibility.
- Conformance fixtures (`conformance/fixtures/`) for cross-SDK protocol
  validation.
- Threat model documentation (`docs/THREAT-MODEL.md`).
- Security policy (`.github/SECURITY.md`).
- Examples: SaaS multi-tenant, telecom provisioning, AI/MCP tool governance,
  and payment reconciliation.

### Changed

- `runtime.Dependencies` accepts an optional `Tracer` for distributed tracing.
- `observability/otel.Bridge` implements `runtime.Tracer` in addition to
  `Observer` and `ActiveObserver`.
- `app.Config` accepts an optional `Tracer`.
- Durable-store and recovery metrics are now written by the runtime and
  recovery worker; previously exported but never populated.
- `loom_execute_duration_seconds` is now a full histogram with `_sum`,
  `_count`, and `le` buckets.
- Release documentation updated to reflect trusted-publisher SDK publication.

### Fixed

- npm SDK publication auth failure caused by the workflow unsetting
  `NODE_AUTH_TOKEN` after upgrading npm globally.

## [0.2.1] — 2026-08-07

### Fixed

- The release publish job downloaded artifacts without checking out the
  repository, so `scripts/verify-release-artifacts.sh` was absent and
  publication failed after every artifact had already been built, signed, and
  attested. Checkout now precedes the download, which would otherwise clear the
  downloaded `dist` directory.
- `SHA256SUMS` was never attached to a release. The publish step globbed
  `dist/loom-*`, which does not match the manifest, so `scripts/install.sh` —
  which fetches it with `curl --fail` and verifies the binary against it —
  could not succeed for any release, including v0.2.0 and earlier.
- The checksum and signature jobs depended only on the binaries, so the SBOM
  was absent from `dist` when they ran and was therefore neither checksummed
  nor signed. This silently negated the earlier removal of the `*sbom*.json`
  and `*.json` exclusions from those steps. Both jobs now also depend on the
  SBOM job.
- The Python, TypeScript, and Rust SDK `User-Agent` strings were pinned to
  0.1.8 and had not moved since that release, so `scripts/check-sdk-versions.sh`
  failed against the release version. They now track the release.
- `container-scan` filtered its push trigger by path, and GitHub applies that
  filter to tag pushes as well, so a release commit touching only `VERSION`
  and documentation never scanned. The release gate requires a `container-scan`
  success at the exact tag SHA, which made such a release unpublishable. The
  push trigger no longer filters by path; pull requests still do.

## [0.2.0] — 2026-08-07

### Breaking

- `loom audit rotate` now requires `--checkpoint` and
  `LOOM_AUDIT_CHECKPOINT_KEY_PREVIOUS`. It verifies the prior checkpoint under
  the retired key before re-signing with the current key; previously it
  re-signed without checking anything, so the new key could attest to history
  the retired key never covered. Existing invocations exit 2 until updated.
- `runtime.Metrics.ObserveRecovery` is replaced by `ObserveRecoveryQueue`
  (depth and oldest age) and `ObserveRecoveryProgress` (attempts, renewals,
  dead letters). The combined signature forced a caller that knew only the
  counters to pass a zero depth, silently resetting a gauge set elsewhere.
- `oidc.NewVerifier` now fetches the JWKS during construction, so an
  unreachable key endpoint fails at startup rather than on the first
  authenticated request.

### Added

- `loom audit verify-checkpoint` checks a stored checkpoint against the events
  it attests, so an auditor can confirm one with the tool that produced it.
- `loom audit export --stream` exports a verified segment from the durable
  PostgreSQL audit stream; `--from` and `--to` are required.
- `bootstrap.Config.ReadyChecks` registers application-owned readiness probes,
  and `oidc.Verifier.ReadyCheck` plugs the verifier into `/readyz`.

### Fixed

- Durable-store and recovery metrics were exported but never written, so
  `loom_recovery_depth` and the durable-store series read zero forever while
  the documentation recommended alerting on them. The runtime now reports
  execution-status write latency and failures, and the recovery worker reports
  queue depth, oldest-record age, attempts, renewals, and dead letters.
- `loom_execute_duration_seconds` was missing `_sum`, so average latency could
  not be computed from the histogram.
- `/readyz` reported ready when an application-supplied identity verifier had
  never reached its issuer, serving traffic that denied every authenticated
  request.
- PostgreSQL audit export could never verify a chain written on a platform
  whose clock has nanosecond resolution. `TIMESTAMPTZ` stores microseconds and
  rounds anything finer, so the stored hash committed to a timestamp the
  database could not return. Event timestamps are now rounded to microseconds
  before hashing.
- Release checksum generation now preserves downloaded binary artifacts by
  checking out source before downloading them.
- The PyPI publication action is pinned to a valid container-backed release.

### Changed

- Release reruns can target an existing immutable tag and publish the requested
  GitHub Release instead of the workflow's branch ref.
- SDK publication documentation now lists the exact PyPI, npm, and crates.io
  trusted-publisher configuration; npm clears injected token authentication
  before attempting OIDC publication.


## [0.1.8] — 2026-08-07

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
