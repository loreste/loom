# Loom v1 implementation evidence report

Evidence report for the repository at release **v1.0.1**. This is not a claim
that every external production-readiness condition (pen test, multi-replica
soak, public SDK registry installs) is complete.

## Release identity

| Item | Value |
| --- | --- |
| Version | `1.0.1` ([`VERSION`](../VERSION)) |
| Tag | `v1.0.1` |
| Python distribution | `loreste-loom` (import `loom`; never PyPI `loom-sdk`) |
| npm / crates | intended coordinates unpublished until trusted publishers succeed |

## Security and correctness (v1.0.x)

- **OIDC/JWKS** (`identity/oidc`): discovery, exact issuer/audience, algorithm
  allowlist, clock skew on `exp`/`nbf`, rotation, size/TLS/timeout limits,
  readiness. CLI/bootstrap: `LOOM_OIDC_*`.
- **Recovery**: leases, heartbeat, backoff, dead-letter, escalation dedup;
  never re-runs business handlers; does not unwind successful reconcile on late
  lease-renewal failure.
- **Policy**: strict JSON (unknown fields, duplicate keys, effect enum, bounds);
  empty rules = deny-all; failed reload preserves active policy.
- **Webhooks**: SSRF-safe destinations, signed envelopes; durable path enqueues
  `loom_webhook_outbox` in the same Postgres transaction as audit; production
  refuses inline nondurable delivery; `loom webhook-worker` + Helm worker.
- **Docs/manifest honesty**: `release-manifest.json` and CI gates prevent false
  “SDK published” claims.

## Operations packaging

- CLI: policy lint/test/diff/explain/simulate; execution get; recovery
  list/requeue/dead-letter; audit head/verify/export/checkpoint/rotate;
  recovery-worker; webhook-worker.
- Helm: API, recovery worker, webhook worker (when URL set), migration job,
  PDB, NetworkPolicy, probes, non-root defaults.
- Examples: saas, ai-mcp, payment-reconciliation, telecom, etc.
- Observability: bounded metrics including recovery and webhook queue signals;
  OpenTelemetry bridge.

## Verification (local and CI)

Local gates run for the release commit family:

```text
go mod verify
go vet ./...
go test ./...
go test -race (focused packages)
go test -fuzz=FuzzExecute -fuzztime=10s ./runtime/
go build ./...
sh scripts/check-sdk-versions.sh
sh scripts/check-release-manifest.sh
Python / TypeScript / Rust SDK unit tests
```

GitHub Actions on tag `v1.0.1` (representative):

```text
ci.yml (all jobs)           success
security                    success
container-scan              success
dependency-review           success
release (binaries, SBOM,
  checksums, signatures,
  provenance, publish)      success
```

## Deferred external evidence

- Independent penetration test and remediation record.
- Public registry installation of Python/npm/crates packages.
- Multi-replica (1/10/50) failover and 24-hour soak reports with hardware
  metadata.
- WORM archival and KMS/HSM checkpoint signers (deployment-owned).
- NetworkPolicy default-deny egress allowlists for Postgres/Redis/webhooks.

## Compatibility

Additive fields, optional interfaces, and Postgres schema v6 webhook outbox.
Apply migrations before upgrading API or workers. Follow
[`COMPATIBILITY.md`](COMPATIBILITY.md).
