# Changelog

All notable changes to Loom are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-05

Initial public version.

### Added

- Embed-first governance runtime (`app`, `runtime`, policy, guardrails, approval, quotas, idempotency, audit)
- Secure DB layer (`db` pools, SQL guard, migrator, `db.query` / `db.exec`)
- Optional edges: HTTP, MCP, GraphQL, gRPC, CLI, Weft
- Agent discovery: `catalog.spec`, OpenAPI export, `/.well-known/loom.json`
- Postgres + Redis durable backends; file/memory fallbacks
- Cross-platform CLI builds (Linux / macOS / Windows, amd64 + arm64)
- Docker image, install script, CI cross-compile + release workflows
- Security hardening (approval claim-before-exec, mTLS peer binding, prod defaults)
- Docs: EMBED, SECURITY, TENANCY, BUILD

### Notes

- Product version is maintained in the root `VERSION` file.
- Git tags use the form `v0.1.0`.
