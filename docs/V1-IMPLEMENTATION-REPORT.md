# Loom v1 implementation evidence report

This report records the implementation work in the current worktree. It is an
evidence report, not a claim that external production-readiness conditions
have already occurred.

## Phase 1 — identity and recovery

- `identity/oidc/` provides configured HTTPS issuer discovery, exact issuer and
  audience validation, algorithm allowlists, bounded token/discovery/JWKS
  responses, key rotation refresh, claim mapping, optional introspection, and
  readiness counters.
- `recovery/worker.go` and the execution stores provide guarded leases,
  heartbeat renewal, attempts, bounded exponential backoff with deterministic
  jitter, operator review/dead-letter state, escalation deduplication, and
  provider verification without business-handler replay.
- `store/postgres/execution.go` provides PostgreSQL lease, scheduling,
  reconciliation, and approved recovery administration transitions.

Security invariants preserved: authentication remains separate from
authorization; unknown or stale credentials deny; tenant boundaries are
verified; leases are bound to execution and lease IDs; approval and
idempotency state precede side effects; recovery never invokes a business
handler; uncertain side effects remain `executed_unconfirmed`.

Tests include OIDC claim/time/algorithm/issuer/audience/rotation/size/TLS/
timeout/concurrent-refresh cases, recovery backoff/dead-letter/escalation/
heartbeat cases, PostgreSQL integration lease races, and reconciliation
state-transition tests.

## Phase 2 — distribution and release integrity

- Release workflows build cross-platform binaries, generate checksums, SBOMs,
  Cosign bundles, and build provenance.
- Release publication requires exact-commit success for CI, security,
  dependency-review, and container scanning.
- `scripts/generate-checksums.sh` includes release SBOMs.
- `scripts/verify-release-artifacts.sh` verifies every manifest asset and
  requires its Sigstore bundle.
- Container publication targets Linux amd64/arm64, non-root distroless
  runtime, SBOM attestation, Cosign signing, and provenance.
- SDK publication includes trusted PyPI, npm, crates.io, and Go module-proxy
  installation checks.

No credentials or demo secrets are embedded in release artifacts. Actions are
pinned to full commit SHAs and Dependabot tracks action updates.

## Phase 3 — operations, references, and audit lifecycle

- CLI policy lint/test/diff/explain/simulate, execution status, recovery
  administration, audit head/verify/export/checkpoint/rotate are implemented.
- PostgreSQL audit stream export verifies bounded sequence ranges against a
  trusted prior hash. Checkpoints use a signer interface; production guidance
  requires KMS/HSM key management and WORM-capable archival where applicable.
- `examples/saas/` documents PostgreSQL RLS tenant isolation.
- `examples/ai-mcp/` demonstrates governed AI/MCP calls, approval, constrained
  output, and non-authorizing discovery.
- `examples/payment-reconciliation/` demonstrates safe
  `executed_unconfirmed` provider reconciliation without handler replay.
- `examples/telecom/` covers SIP trunk, DID, routing, and credit operations
  with tenant boundaries, explicit versions, approvals, idempotency, and
  audit behavior.
- `conformance/fixtures/execute-semantics.v1.json` defines versioned,
  language-neutral deny/contract semantics for SDK publication tests.
- Helm deployment manifests separate API, recovery worker, and migration job,
  with PDB, NetworkPolicy, probes, non-root/read-only defaults, and minimum
  ServiceAccount permissions.

## Phase 4 — observability and performance evidence

`runtime.Metrics` and the OpenTelemetry bridge expose bounded execution
histograms, active executions, durable-store aggregates, recovery depth/age/
attempt/renewal/dead-letter signals, decisions, stable reasons, and stage
dimensions without secrets or high-cardinality identifiers. Adapter benchmark
coverage includes in-process, HTTP, MCP, GraphQL, gRPC, and Weft. The
resilience runner requires real PostgreSQL and Redis and records metadata and
raw output; it does not misrepresent in-memory results as production capacity.

## Exact verification results

With a temporary local-only `go.mod` version override from 1.26.5 to the
installed Go 1.26.2 toolchain, then restoring `go.mod` to 1.26.5:

```text
go test ./...                         PASS
go vet ./...                          PASS
go build ./...                        PASS
go test -race ./...                   PASS
go test -fuzz=FuzzExecute -fuzztime=15s ./runtime PASS
focused OIDC/runtime/CLI/examples    PASS
Python SDK unit tests                PASS (one opt-in contract test skipped)
TypeScript build/lint/tests           PASS
Rust cargo fmt/test/Clippy            PASS
```

Always-pass static checks in the current worktree:

```text
gofmt changed Go files               PASS
workflow YAML parsing                PASS
all workflow action SHA validation   PASS
sh -n scripts/*.sh                   PASS
git diff --check                     PASS
```

## Scans and unavailable checks

The repository contains blocking CI workflows for govulncheck, gosec,
Gitleaks, CodeQL, dependency review, SBOM generation, and Trivy. The
documented govulncheck and gosec commands were attempted; both were blocked by
DNS resolution failure for `proxy.golang.org`. Trivy, Helm, and Actionlint are
not installed locally. Python wheel build tooling could not be installed
because PyPI DNS was unavailable. The default Go 1.26.5 invocation cannot
download its toolchain under the current filesystem policy.

## Compatibility and migration impact

The changes add optional interfaces, metrics, CLI commands, examples, CI
workflow gates, and additive audit/recovery fields. PostgreSQL migrations are
additive and version-guarded; no existing operation version is silently
rebound. Production deployments must apply migrations before upgrading API or
recovery workers and must follow [`COMPATIBILITY.md`](COMPATIBILITY.md).

## Deferred external evidence and risks

- An independent penetration test and remediation record are still required.
- Public registry publication and installation checks require configured
  trusted publishers and network access.
- One/ten/fifty-replica PostgreSQL/Redis failover tests and a minimum 24-hour
  soak report must be run in deployment infrastructure.
- WORM archival, KMS/HSM signers, PostgreSQL RLS roles, identity-provider
  configuration, and provider reconciliation are deployment-owned controls.
- No pull request or commit was created in this worktree; commit identifiers
  are therefore not applicable.
