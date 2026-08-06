# Production identity integration

Loom authenticates a presented credential; it is not an identity provider.
Production applications should inject an `identity.Verifier` through
`app.Config.IdentityVerifier` or wire one into `runtime.Dependencies`.

## OIDC and JWKS integration checklist

An application-provided OIDC/JWKS integration should:

- discover issuer metadata from configured input and pin the expected issuer
  and audience;
- cache JWKS keys with bounded freshness, refresh on an unknown `kid`, and keep
  an overlap window during key rotation;
- allow only explicitly supported algorithms;
- reject missing or expired `exp`, invalid `nbf`, wrong issuer, wrong audience,
  oversized tokens, and malformed claims;
- map subject, service identity, identity type, and tenant/boundary claims
  through explicit configuration;
- define revocation behavior, such as short-lived tokens, introspection, or a
  deny-list; and
- expose verifier health, key-refresh failures, issuer changes, and clock
  errors to operators.

Loom does not currently ship an OIDC discovery or JWKS-rotation client. The
built-in HMAC JWT verifier is intended for controlled deployments and tests;
configure its secret, issuer, audience, and claim mapping explicitly.

## mTLS integration

Use the verified TLS peer certificate path with
`identity.CredentialsFromCertificate`. Do not authenticate a caller from a
fingerprint supplied in a request header or body. Certificate rotation belongs
to the TLS-terminating deployment and should be observable by operators.

## Development credentials

The platform bootstrap can seed development-only principals and tokens. They
are useful for examples and tests, but must not be enabled in production.

Production-like CLI configuration should include:

```bash
export LOOM_ENV=production
export LOOM_DISABLE_DEMO_PRINCIPALS=true
export LOOM_REQUIRE_DURABLE=true
export LOOM_JWT_SECRET='<value supplied by your secret manager>'
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

Embedded applications should configure `JWTConfig.ClaimAttributes` and
`tenancy.NewResolver` directly. See [`TENANCY.md`](TENANCY.md).
