# Why Loom exists

Loom has been used internally for the past two months. We are now publishing
it as open source so the implementation, examples, and trade-offs can be
reviewed by other teams. The current release is v0.1.4 and remains an early
release; production identity, deployment, and database isolation still belong
to the integrating application.

Loom is an embed-first governance runtime for Go applications. It gives an
application one controlled execution path for operations that can change data,
move money, affect access, or trigger external side effects.

An operation might be a product action such as `order.create`, a database
query, a background job, a payment, a provisioning request, or an
administrative action. Loom evaluates the request before the handler or
database executor runs it. The same decision path can be reached from in-process
Go code or through HTTP, MCP, GraphQL, gRPC, and Weft adapters.

## From internal use to open source

Loom has been used internally for the past two months to address these
governance and security problems in real application workflows. We are now
open-sourcing it so the implementation can be inspected, adopted by other
teams, and improved in the open. The v0.1.4 release is an early public release:
the core runtime is substantial, while packaging, production integrations, and
documentation will continue to mature with community use.

## The problem

As an application grows, sensitive work usually becomes reachable through more
than one path:

- an HTTP endpoint for the web application;
- a worker that retries a job later;
- an administrative CLI;
- an MCP or GraphQL tool;
- an internal service using gRPC; and
- code that runs directly inside the process.

Without a shared enforcement point, each path tends to grow its own combination
of authentication, authorization, tenant checks, input validation, approval
logic, and audit events. That creates security drift:

- one adapter checks a permission while another forgets it;
- a worker can perform an operation that the HTTP path denies;
- product code reaches a database directly and bypasses policy;
- retries duplicate payments or other side effects;
- approval tokens are reused under concurrency;
- tenant context is lost between the request and the database; and
- operators cannot tell why a request was denied.

The result is not only a security problem. It is also a maintenance problem:
teams repeatedly design and test the same authorization boundary while the
number of callers continues to increase.

## Why an application like Loom is needed

Loom makes the execution boundary explicit. Application code registers named
operations and their handlers, then calls `app.Call` or `Runtime.Execute`.
Adapters translate external requests into that call; they do not implement a
second authorization system.

This gives teams a consistent place to apply controls that are otherwise easy
to omit:

```text
caller or adapter
        |
        v
identity → boundary → operation policy → resource policy → context policy
        → guardrails → risk/approval → idempotency → quota
        → handler or governed database executor → output filtering → audit
```

The default is deny. Unknown operations, missing rules, invalid boundaries,
failed verification, and enforcement errors fail closed. Single-use approvals
are consumed before side effects, idempotency protects retries, and governed
database access applies conservative SQL checks in addition to database-level
controls.

## What Loom is for

Loom is a good fit when an application needs several of these at once:

- one authorization model across synchronous requests and background work;
- explicit tenant or boundary enforcement;
- controlled access to application databases;
- approvals for high-risk actions;
- quotas and replay protection;
- consistent output filtering and secret redaction; and
- an audit trail and operational view of decisions.

Typical governed operations include customer-data access, telecom
provisioning, credit or payment changes, account administration, data exports,
and agent-accessible tools.

## What Loom is not

Loom is not an identity provider, an OAuth/OIDC service, an ORM, or a guarantee
of tenant isolation by itself. Production deployments still need a real
identity verifier, restricted database roles, PostgreSQL RLS or equivalent
isolation, timeouts, connection limits, durable security state, and operational
monitoring.

Loom governs what happens after a caller presents an identity. It does not
invent an application's domain model or replace careful database and network
design.

## The design goal

The goal is simple: sensitive application operations should have one obvious,
testable, observable path from caller to side effect. Adding a new protocol or
worker should add a translation layer, not a new privilege path.

Continue with:

- [`INSTALL.md`](INSTALL.md) for building Loom, installing a release, using
  Docker, or adding an SDK;
- [`HOWTO.md`](HOWTO.md) for operation, database, approval, job, and observability
  recipes;
- [`EMBED.md`](EMBED.md) for the in-process API; and
- [`SECURITY.md`](SECURITY.md) for the security model and production limits.
