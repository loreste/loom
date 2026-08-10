# Production identity integration

Loom authenticates presented credentials; it is not an identity provider or a
tenant directory. Production applications inject an `identity.Verifier` through
`app.Config.IdentityVerifier`, wire one into `runtime.Dependencies`, or enable
the CLI/bootstrap OIDC path with `LOOM_OIDC_*` environment variables.

Authentication never grants an operation. After identity is established, Loom
still evaluates policy, boundary membership, resources, and fields.

## OIDC and JWKS (first-class bootstrap)

As of v1.0.1, setting `LOOM_OIDC_ISSUER` on the CLI or any process that uses
`config.PlatformConfig()` → `bootstrap.NewPlatform` constructs
[`identity/oidc`](../identity/oidc) automatically:

- registers scheme `oidc`;
- tries OIDC for `bearer` credentials after the HMAC JWT verifier fails;
- registers `verifier.ReadyCheck()` so `/readyz` fails until discovery and
  JWKS fetch have both succeeded.

```bash
export LOOM_OIDC_ISSUER='https://issuer.example/realms/loom'
export LOOM_OIDC_AUDIENCE='loom-api'
export LOOM_OIDC_ALGS='RS256'
export LOOM_OIDC_CLAIM_BOUNDARY='tenant_id'   # default
export LOOM_OIDC_REQUIRE_BOUNDARY=true        # default
```

Full variable table: [`CONFIGURATION.md`](CONFIGURATION.md).

The package performs HTTPS discovery, exact issuer and audience validation,
an explicit signing-algorithm allowlist, JWKS refresh on unknown `kid`, and
bounded token/upstream response sizes. Claim names for boundaries, roles,
capabilities, and attributes remain application configuration—they are not
assumed from a vendor template.

### Embedded application (manual wiring)

```go
oidcVerifier, err := oidc.NewVerifier(ctx, oidc.Config{
	Issuer:            os.Getenv("LOOM_OIDC_ISSUER"),
	Audience:          os.Getenv("LOOM_OIDC_AUDIENCE"),
	AllowedAlgorithms: []string{"RS256"},
	ClaimBoundary:     "tenant_id", // same as LOOM_OIDC_CLAIM_BOUNDARY
	RequireBoundary:   true,
	ClaimCapabilities: "capabilities",
	ClaimRoles:        "roles",
	RoleCapabilities:  configuredRoleCapabilities(),
	ClaimAttributes:   map[string]string{"email": "email"},
})
if err != nil {
	return err
}

// Embedded app:
app, err := app.New(app.Config{IdentityVerifier: oidcVerifier})

// Or platform bootstrap with readiness:
// bootstrap.Config{OIDC: bootstrap.OIDCConfig{...}, ReadyChecks: []func(context.Context) error{oidcVerifier.ReadyCheck()}}
// Note: when using config.PlatformConfig() with LOOM_OIDC_ISSUER set, ReadyCheck is registered automatically.
```

Use a secret-managed issuer and audience. Do not accept arbitrary issuer or
algorithm values from a request. Export `Health()` counters through approved
observability integrations without adding tokens, subjects, tenant IDs, or raw
claims to metric labels.

`NewVerifier` performs issuer discovery and fetches the key set before it
returns, so an unreachable issuer or JWKS endpoint fails at startup rather than
on a caller's first authenticated request.

For a generic provider, configure its issuer URL, client audience, and the
provider's documented claim names. For Keycloak, use the realm issuer URL and
map the configured realm claim or protocol mapper to the boundary claim; do
not infer a tenant from a group name unless the provider is explicitly
configured to issue that claim.

The verifier validates `exp`, `iat`, and `nbf` with conservative, configurable
clock skew (including `exp` leeway). An optional `Introspector` can add
revocation or active-token checks; an introspection error denies authentication.
Certificate validation remains the responsibility of the configured TLS client.

## OIDC deployment checklist

- use a configured HTTPS issuer and exact audience;
- allow only explicitly supported signing algorithms (`none` is rejected);
- keep token, discovery, and JWKS responses within configured bounds;
- refresh keys on an unknown `kid` and retain provider rotation overlap;
- map subject, service identity, identity type, tenant/boundary, roles,
  capabilities, and attributes through explicit configuration;
- define revocation behavior, short-lived tokens, and optional introspection;
- ensure `/readyz` includes OIDC readiness (automatic for CLI when
  `LOOM_OIDC_ISSUER` is set);
- test issuer, audience, algorithm, expiry, not-before, claim, rotation,
  oversized-response, timeout, and tenant-mismatch failures.

## HMAC JWT verifier

The built-in HMAC verifier is intended for controlled deployments and tests.
Configure its secret, issuer, audience, and claim mapping via `LOOM_JWT_*`.
It does not provide issuer discovery or key rotation; use OIDC when those
behaviors are required.

Bearer credentials try, in order: static/demo principals, HMAC JWT, then OIDC
when each is configured.

## mTLS integration

Use the verified TLS peer certificate path
`identity.CredentialsFromCertificate`. Do not authenticate a caller from a
fingerprint supplied in a request header or body. Certificate rotation belongs
to the TLS-terminating deployment and should be observable by operators.

## Development credentials

Platform bootstrap can seed development-only principals and tokens. They are
useful for examples and tests, but must not be enabled in production:

```bash
export LOOM_ENV=production
export LOOM_DISABLE_DEMO_PRINCIPALS=true
export LOOM_REQUIRE_DURABLE=true
export LOOM_JWT_SECRET='<value supplied by secret manager>'
export LOOM_JWT_KEY_ID='active-key'
export LOOM_JWT_ISSUER='https://issuer.example'
export LOOM_JWT_AUDIENCE='loom-api'
# Optional production OIDC (in addition to or instead of HMAC JWT for callers):
export LOOM_OIDC_ISSUER='https://issuer.example/realms/loom'
export LOOM_OIDC_AUDIENCE='loom-api'
```

## Tenant claim mapping

For CLI configuration, copy a verified JWT claim into Loom's standard tenant
attribute:

```bash
export LOOM_TENANT_CLAIM=tenant_id
```

With OIDC, boundary mapping uses `LOOM_OIDC_CLAIM_BOUNDARY` (default
`tenant_id`). Embedded applications should configure the verifier's explicit
boundary claim and `tenancy.NewResolver` directly. See [`TENANCY.md`](TENANCY.md).
