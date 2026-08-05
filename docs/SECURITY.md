# Loom security notes (white-hat review)

Last review: 2026-08-05. Scope: full pipeline + all adapters + bootstrap defaults.

## Non-negotiables (status)

| Control | Status |
|---------|--------|
| Default DENY | Hold |
| Fail closed | Hold |
| Single entrypoint (`Runtime.Execute`) | Hold — all adapters |
| No adapter privilege / bypass headers | Hold — tripwires deny |
| Core free of adapters | Hold |
| Secrets not in caller denials | Hold (`SafeDenial`) |
| Approval tokens hashed | Hold |
| SQL fail-closed class + allowlist | Hold (hardened) |

## Fixes applied this review

1. **Approval dual-exec (CRITICAL)** — `Consume` now claims the single-use token **immediately before the handler** (after Evaluate + quotas + idempotency Begin). Concurrent callers: exactly one allow. Handler failure burns the token (fail closed for money ops).
2. **Idempotency Complete after success** — errors are logged; key is **not** aborted after a successful handler (prevents second side-effect).
3. **Postgres idempotency Begin race** — insert uses `ON CONFLICT DO NOTHING`; lost races return conflict.
4. **Approval Issue cannot resurrect tokens** — memory/file/postgres refuse re-issue of an existing/consumed hash.
5. **mTLS fingerprint spoofing (HIGH)** — `MTLSVerifier` requires `Claims["peer_verified"]=1`, set only by `CredentialsFromCertificate` (HTTP TLS peer). Weft/body cannot forge mTLS with a known fingerprint.
6. **MCP HTTP auth precedence (HIGH)** — transport `Authorization` locks the token; JSON-RPC body cannot override.
7. **SQL allowlist empty-table bypass (HIGH)** — with non-empty `AllowedTables`, statements that extract zero tables are denied.
8. **`catalog.list` enumeration (MEDIUM)** — capability-filtered like `catalog.spec`.
9. **GraphQL recon (MEDIUM)** — introspection disabled by default; body limit follows HTTP `MaxBodyBytes`.
10. **Hostile header coverage** — shared `applyHostileHeaders` on execute + aliases.
11. **Production serve hardening** — `LOOM_ENV=production|staging` requires `LOOM_DISABLE_DEMO_PRINCIPALS`, `LOOM_JWT_SECRET`, and `LOOM_REQUIRE_DURABLE`. Demo tokens log a loud WARNING.
12. **CLI god-paths** — `mint-jwt`, `approve`, `--issue-approval` require `LOOM_DEV_TOOLS=1`.
13. **NetworkGuard DNS** — hostnames are resolved; any private/link-local/metadata answer is denied; DNS errors fail closed. Nested `url`/`host` fields scanned.
14. **gRPC on serve** — `--grpc-addr=:9090` (or `LOOM_GRPC_ADDR`) starts `loom.v1.Runtime/Execute` with 1 MiB message caps.
15. **HTTP edge rate limit** — `LOOM_HTTP_RATE_LIMIT` (req/min per IP); healthz/readyz exempt; does not trust `X-Forwarded-For`.
16. **GraphQL credentials** — same `ExtractCredentials` as HTTP (bearer + mTLS peer cert).

## Residual risk (accepted / deferred)

| Item | Severity | Notes |
|------|----------|--------|
| Demo principals in default **development** serve | MED | Intentional for demos; production profile blocks them |
| CLI `approve` / `mint-jwt` | LOW | Gated by `LOOM_DEV_TOOLS=1` |
| Nested field ACL depth | MED | Field grants still top-level `*`; secrets redacted recursively |
| No edge rate limit before auth | LOW | Rely on reverse proxy |
| DB multi-tenant row isolation | HIGH if shared pool | Use per-tenant pools/RLS — Loom policy is not RLS |
| Complete failure leaves key in-flight until TTL | LOW | Preferable to double side-effect |
| NetworkGuard DNS | mitigated | Resolves hostnames; any private/link-local answer denied; DNS errors fail closed |

## Serve surfaces

```bash
loom serve --addr=:8080 --grpc-addr=:9090
# HTTP:  /v1/execute, /mcp, /graphql, /.well-known/loom.json, /v1/openapi.json
# gRPC:  loom.v1.Runtime/Execute  (MaxRecvMsgSize 1MiB)
```

## Production checklist

```bash
export LOOM_ENV=production
export LOOM_DISABLE_DEMO_PRINCIPALS=true
export LOOM_REQUIRE_DURABLE=true
export LOOM_DATABASE_URL='postgres://…'
export LOOM_JWT_SECRET='…'   # ≥16 bytes, not dev-only*
# optional
export LOOM_REDIS_URL='redis://…'
export LOOM_QUOTA_FAIL_CLOSED=true
```

## Adversarial tests of note

- `runtime/hardening_test.go` — concurrent approval consume, burn-before-exec, audit fail-closed
- `identity/mtls_test.go` — forged fingerprint rejected
- `adapters/http/wiring_security_test.go` — GraphQL wired + bypass; MCP header wins over body
- Existing adapter bypass tests (HTTP/MCP/gRPC/Weft)

## How to re-audit

```bash
go test -race ./...
go test -fuzz=FuzzExecute -fuzztime=15s ./runtime/
```
