# Loom documentation

This index describes the current repository and points to the guide that fits
each task.

## Start here

| Need | Guide |
| --- | --- |
| Understand the problem Loom solves | [`OVERVIEW.md`](OVERVIEW.md) |
| Install the CLI, Docker image, Go module, or SDKs | [`INSTALL.md`](INSTALL.md) |
| Configure environment variables and server flags | [`CONFIGURATION.md`](CONFIGURATION.md) |
| Make a first governed call | [`HOWTO.md`](HOWTO.md) |
| Use Loom from Go, Weft, Python, Node.js, or Rust | [`SDK.md`](SDK.md) |
| Embed Loom without an HTTP server | [`EMBED.md`](EMBED.md) |
| Call the HTTP API or execution-status endpoints | [`API.md`](API.md) |

## Design and security

| Topic | Guide |
| --- | --- |
| Runtime guarantees and deployment boundaries | [`SECURITY.md`](SECURITY.md) |
| Identity verifier integration | [`IDENTITY.md`](IDENTITY.md) |
| Tenant boundaries and PostgreSQL RLS | [`TENANCY.md`](TENANCY.md) |
| Bounded input/output schema | [`SCHEMA.md`](SCHEMA.md) |
| Protocol, operation, and SDK compatibility | [`COMPATIBILITY.md`](COMPATIBILITY.md) |

## Operating and contributing

| Topic | Guide |
| --- | --- |
| Metrics, tracing, and safe telemetry | [`OBSERVABILITY.md`](OBSERVABILITY.md) |
| Production runbook and failure handling | [`OPERATIONS.md`](OPERATIONS.md) |
| Execution recovery worker and reconciliation | [`RECOVERY.md`](RECOVERY.md) |
| Performance benchmark and measurement guidance | [`PERFORMANCE.md`](PERFORMANCE.md) |
| Failure-injection scenarios and results | [`FAILURE-INJECTION.md`](FAILURE-INJECTION.md) |
| Local checks and release artifacts | [`BUILD.md`](BUILD.md) |
| Package, image, and artifact publication | [`RELEASES.md`](RELEASES.md) |
| Kubernetes and Helm deployment | [`KUBERNETES.md`](KUBERNETES.md) |
| Release history | [`../CHANGELOG.md`](../CHANGELOG.md) |

## Examples and source

- [`../examples/orders-app/`](../examples/orders-app/) shows an embedded
  application with governed SQLite access.
- [`../examples/embed/`](../examples/embed/) shows governed database calls
  without an HTTP server.
- [`../examples/worker/`](../examples/worker/) shows background jobs using the
  same `app.Call` path.
- [`../examples/tenancy/`](../examples/tenancy/) shows the application and
  PostgreSQL RLS sides of tenant isolation.
- [`../adapters/conformance/`](../adapters/conformance/) contains adapter
  conformance tests.

The root [`README.md`](../README.md) is the short project introduction. The
root [`VERSION`](../VERSION) file is the release source of truth.
