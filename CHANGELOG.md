# Changelog

All notable changes to Loom are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] — 2026-08-05

### Added

- Formal bounded Loom Schema contract and validation resource limits.
- Exact operation-version binding for handlers, policies, approvals, idempotency, responses, and execution status.
- Execution status, reconciliation, and recording-retry APIs with execution IDs.
- Effect-aware production capability validation, currency allow-lists, signed `MoneyDelta`, and cross-adapter conformance coverage.

### Changed

- Added Node.js and Weft SDK usage documentation and released SDK metadata at `0.1.4`.

## [0.1.3] — 2026-08-05

### Added

- Exact `core.Money` financial limits and payment-handler arithmetic.
- Bounded Loom Schema validation for handler output, with unsupported-keyword rejection.
- Separate input-field authorization, structured boundary context, exact operation versions, and execution IDs.
- Explicit `executed_unconfirmed` outcomes, idempotency recovery enqueueing, and Node/Weft SDK support.

### Changed

- Production runtime mode rejects implicit process-local security state and empty guardrail chains.
- Quota refunds after handler errors are opt-in; charging begins when execution starts.
- PostgreSQL migration bootstrap now serializes concurrent runners so two
  application instances cannot apply the same migration at once.

## [0.1.2] — 2026-08-05

### Changed

- Security pipeline hardening and tenant-isolation controls were added.

## [0.1.1] — 2026-08-05

### Added

- Public installation, build, identity, observability, compatibility, and
  tenancy guidance.
- Cross-SDK CI and contract tests for Python, TypeScript, and Rust clients.
- Release packaging for source builds, Docker, and cross-platform binaries.
- Tenant claim resolution, tenant-bound PostgreSQL transactions, an RLS
  reference migration, and cross-tenant adversarial tests.

### Changed

- Production construction can require durable security state and explicit
  identity integration.
- Loom documents its internal two-month usage history and open-source release
  context.
- Security-sensitive defaults now require verified mTLS peers, explicit metrics
  access, generated development credentials, and tenant context for configured
  shared PostgreSQL pools.

## [0.1.0] — 2026-08-05

Initial public version.

### Added

- Embed-first governance runtime (`app`, `runtime`, policy, guardrails, approval, quotas, idempotency, audit)
- Secure DB layer (`db` pools, SQL guard, migrator, `db.query` / `db.exec`)
- Optional edges: HTTP, MCP, GraphQL, gRPC, CLI, Weft
- Agent discovery: `catalog.spec`, OpenAPI export, `/.well-known/loom.json`
- Postgres + Redis durable backends; file/memory fallbacks
- Cross-platform CLI builds (Linux / macOS / Windows, amd64 + arm64), Dockerfile,
  installer, Makefile, and release workflow (see [`docs/BUILD.md`](docs/BUILD.md))
- Security hardening (approval claim-before-exec, mTLS peer binding, prod defaults)
- Docs: EMBED, SECURITY, TENANCY, BUILD

### Notes

- Product version is maintained in the root `VERSION` file.
- Git tags use the form `vMAJOR.MINOR.PATCH`; this release is tagged `v0.1.0`.
