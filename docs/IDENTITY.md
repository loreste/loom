# Production identity integration

Loom authenticates presented credentials; it is not an identity provider or a
tenant directory. Production applications should inject an `identity.Verifier`
through `app.Config.IdentityVerifier` or wire one into `runtime.Dependencies`.

## OIDC and JWKS verifier

Loom includes [`identity/oidc`](../identity/oidc), an embeddable verifier for
OIDC providers. It performs discovery, validates the exact configured issuer
and audience, uses an explicit signing-algorithm allowlist, refreshes remote
keys when a new `kid` appears, bounds token and upstream response sizes, and
maps verified claims into `core.Identity`. Authentication still does not grant
an operation; the normal Loom policy and boundary gates run afterward.

The verifier requires explicit provider and security configuration. Claim names
for boundaries, roles, capabilities, and attributes are not assumed:

```go
oidcVerifier, err := oidc.NewVerifier(ctx, oidc.Config{
	Issuer:            os.Getenv("LOOM_OIDC_ISSUER"),
	Audience:          os.Getenv("LOOM_OIDC_AUDIENCE"),
	AllowedAlgorithms: []string{"RS256"},
	ClaimBoundary:     os.Getenv("LOOM_OIDC_BOUNDARY_CLAIM"),
	RequireBoundary:   true,
	ClaimCapabilities: os.Getenv("LOOM_OIDC_CAPABILITIES_CLAIM"),
	ClaimRoles:        os.Getenv("LOOM_OIDC_ROLES_CLAIM"),
	RoleCapabilities:  configuredRoleCapabilities(),
	ClaimAttributes:   map[string]string{"email": "email"},
})
if err != nil {
	return err
}

app, err := app.New(app.Config{IdentityVerifier: oidcVerifier})
```

Use a secret-managed issuer and audience. Do not accept arbitrary issuer or
algorithm values from a request. The verifier exposes bounded readiness and
discovery/JWKS counters through `Health()`; export those values through the
application's approved observability integration without adding tokens,
subjects, tenant IDs, or raw claims to labels.

For a generic provider, configure its issuer URL, client audience, and the
provider's documented claim names. For Keycloak, use the realm issuer URL and
map the configured realm claim or protocol mapper to the boundary claim; do
not infer a tenant from a group name unless the provider is explicitly
configured to issue that claim. A managed provider follows the same pattern:
the issuer and audience come from deployment configuration, while the claim
mapping remains application configuration.

The verifier validates `exp`, `iat`, and `nbf` with conservative clock skew.
An optional `Introspector` can add revocation or active-token checks; an
introspection error denies authentication. Certificate validation remains the
responsibility of the configured TLS client.

## OIDC deployment checklist

The OIDC package and its deployment should:

- use a configured HTTPS issuer and exact audience;
- allow only explicitly supported signing algorithms;
- keep token, discovery, and JWKS responses within configured bounds;
- refresh keys on an unknown `kid` and retain provider rotation overlap;
- map subject, service identity, identity type, tenant/boundary, roles,
  capabilities, and attributes through explicit configuration;
- define revocation behavior, short-lived tokens, and optional introspection;
- expose discovery and JWKS health without exposing token or user data;
- test issuer, audience, algorithm, expiry, not-before, claim, rotation,
  oversized-response, timeout, and tenant-mismatch failures.

## HMAC JWT verifier

The built-in HMAC verifier is intended for controlled deployments and tests.
Configure its secret, issuer, audience, and claim mapping explicitly. It does
not provide issuer discovery or key rotation; use `identity/oidc` when those
behaviors are required.

## mTLS integration

Use the verified TLS peer certificate path
`identity.CredentialsFromCertificate`. Do not authenticate a caller from a
fingerprint supplied in a request header or body. Certificate rotation belongs
to the TLS-terminating deployment and should be observable by operators.

## Development credentials

Platform bootstrap can seed development-only principals and tokens. They are
useful for examples and tests, but must not be enabled in production. A
production-like CLI configuration should include values supplied by a secret
manager:

```bash
export LOOM_ENV=production
export LOOM_DISABLE_DEMO_PRINCIPALS=true
export LOOM_REQUIRE_DURABLE=true
export LOOM_JWT_SECRET='<value supplied by secret manager>'
export LOOM_JWT_KEY_ID='active-key'
export LOOM_JWT_ISSUER='https://issuer.example'
export LOOM_JWT_AUDIENCE='loom-api'
```

Authentication does not grant an operation by itself. Loom still requires
explicit policy, boundary membership, resource access, and field grants.

## Tenant claim mapping

For CLI configuration, copy a verified JWT claim into Loom's standard tenant
attribute:

```bash
export LOOM_TENANT_CLAIM=tenant_id
```

Embedded applications should configure the verifier's explicit boundary claim
and `tenancy.NewResolver` directly. See [`TENANCY.md`](TENANCY.md).
