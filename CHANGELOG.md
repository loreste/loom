# Changelog

All notable changes to Loom are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — 2026-08-05

### Added

- Public installation, build, identity, observability, compatibility, and
  tenancy guidance.
- Cross-SDK CI and contract tests for Python, TypeScript, and Rust clients.
- Release packaging for source builds, Docker, and cross-platform binaries.

### Changed

- Production construction can require durable security state and explicit
  identity integration.
- Loom documents its internal two-month usage history and open-source release
  context.

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
- Git tags use the form `vMAJOR.MINOR.PATCH`; this release is tagged `v0.1.1`.
