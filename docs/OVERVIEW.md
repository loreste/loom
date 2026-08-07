# Why Loom exists

Loom has been used internally for the past two months. We are publishing it as
open source so the implementation, examples, and trade-offs can be inspected,
adopted, and improved by other teams.

Loom is an embed-first governance runtime for Go applications. It gives an
application one controlled execution path for operations that can change data,
move money, affect access, or trigger an external side effect.

## The problem

The same sensitive operation often enters through several surfaces:

- an HTTP endpoint;
- a background worker retrying a job;
- an administrative CLI;
- an MCP, GraphQL, or gRPC tool;
- an internal service; or
- code running directly inside the process.

Without a shared execution boundary, applications commonly accumulate
inconsistent rules:

- one adapter checks a permission while another forgets it;
- a worker can perform an operation rejected by the HTTP path;
- product code reaches a database without policy or tenant checks;
- retries duplicate payments or other side effects;
- approval tokens can be reused under concurrency; and
- operators cannot tell which check caused a denial.

## Why an application needs a runtime

An identity provider answers who a caller is. An application policy system
answers what that identity may do. Loom covers the execution boundary between
that decision and the side effect:

```text
caller or adapter
  → verified identity and delegation
  → tenant/boundary resolution
  → operation and resource policy
  → input-field permissions and contextual policy
  → guardrails, risk, approval, idempotency, and quota
  → handler or governed database executor
  → output validation, filtering, redaction, status, and audit
```

The default is deny. The runtime treats an unknown operation, missing policy,
invalid boundary, failed guardrail, or internal enforcement error as a denial.
Adapters cannot skip a stage or grant themselves a capability.

## What Loom provides

- an embedded authorization and execution pipeline;
- a versioned operation registry;
- tenant and boundary checks;
- resource and input/output field authorization;
- guarded database access;
- risk, approval, quota, and idempotency controls;
- exact financial values and declared currency policy;
- output schema validation, filtering, and secret redaction;
- durable execution status and reconciliation hooks; and
- audit and metrics hooks.

HTTP, MCP, GraphQL, gRPC, CLI, Weft, workers, and in-process Go calls are
adapters or callers of the same runtime. They are not separate authorization
implementations.

## What Loom does not provide

Loom is not an identity provider, managed tenant directory, ORM, payment
processor, or database-isolation guarantee. Production applications still need
explicit identity configuration, secret management, restricted database roles,
PostgreSQL RLS where appropriate, tenant-bound transactions, durable storage,
and operational monitoring.

The current release includes HMAC, mTLS, and an embeddable OIDC/JWKS verifier.
Issuer and audience configuration, certificate lifecycle, revocation, and
provider-specific claim mapping remain application integration responsibilities.

## From internal use to open source

The internal deployment gave Loom two months of practical use across governed
operations, database access, workers, and protocol adapters. The public release
is intentionally matter-of-fact: the runtime and test suite are substantial,
while production identity and deployment choices remain visible integration
work rather than hidden assumptions.

See [`VERSION`](../VERSION) for the version source of truth and the
[GitHub releases](https://github.com/loreste/loom/releases) for published
artifacts.
