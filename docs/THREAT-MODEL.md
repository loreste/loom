# Loom threat model

This document describes the trust boundaries and abuse cases that release
review must preserve. It is a design baseline, not a penetration-test report.

## Assets

- Authorization decisions, operation versions, policies, and delegation chains.
- Approval tokens, idempotency reservations, execution state, and recovery
  leases.
- Tenant and boundary membership, provider credentials, and database data.
- Audit events, hash-chain heads, checkpoints, and release provenance.

## Trust boundaries

1. An untrusted caller crosses each HTTP, MCP, GraphQL, gRPC, CLI, Weft, SDK,
   or worker adapter boundary.
2. A verified identity crosses into Loom only after issuer, audience,
   algorithm, time, subject, and configured claim mapping pass.
3. Loom crosses into application handlers only after the common runtime
   pipeline authorizes the exact version and all applicable controls.
4. Loom crosses into PostgreSQL, Redis, identity providers, and external
   providers through separately configured credentials and durable stores.
5. Operators and release automation are privileged actors whose actions must
   be authenticated, approved where required, and audited.

## Attacker goals and controls

| Abuse case | Required control |
| --- | --- |
| Forge or confuse a token algorithm | Explicit issuer, audience, algorithm, time, and JWKS validation; deny on uncertainty |
| Use authentication as authorization | Every adapter enters the same deny-by-default runtime and policy path |
| Cross a tenant or boundary | Verified claims, explicit boundary resolution, and PostgreSQL RLS; application policy is not a substitute for RLS |
| Replay approval or idempotency state | Hash scoped tokens, consume approval before side effects, bind idempotency to principal/boundary/version/fingerprint |
| Bypass controls through an adapter | Adapter conformance tests and no private enforcement bypass |
| Learn resource existence from denials | Stable bounded denial outcomes and resource checks that do not disclose protected identifiers |
| Repeat an uncertain side effect | Immutable execution IDs, `executed_unconfirmed`, durable reconciliation, and recovery that never invokes the business handler |
| Race recovery workers | Database leases guarded by execution ID and lease ID, renewal expiry, attempt limits, and dead-letter state |
| Tamper with audit history | Coordinated stream heads, hash-chain verification, signed checkpoints, and immutable exports |
| Exfiltrate secrets through telemetry | Redaction and bounded labels; never log tokens, SQL, raw bodies, or customer identifiers |
| Publish an unreviewed artifact | Exact-commit CI/security/dependency/container/SDK gates, checksums, signatures, SBOM, and provenance |

## Residual risks and required deployment evidence

Loom does not provide an identity directory, PostgreSQL RLS policy, external
provider truth, KMS/HSM, WORM storage, network isolation, or a universal
revocation service. Deployments must document those controls and test provider
timeouts, database/Redis failure, replica failover, upgrade/rollback, and
24-hour soak behavior. An independent penetration test is required before a
production v1.0 security claim.
