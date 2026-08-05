# Production identity integration

Loom authenticates a presented credential; it is not an identity provider.
Production applications should inject an `identity.Verifier` into
`app.Config.IdentityVerifier` or wire the verifier directly into
`runtime.Dependencies`.

An OIDC/JWKS integration should, at minimum:

- discover issuer metadata from configured input and pin the expected issuer
  and audience;
- cache JWKS keys with bounded freshness, refresh on an unknown `kid`, and
  retain an overlap window during key rotation;
- allow only explicitly supported algorithms and reject missing `exp`, invalid
  `nbf`, wrong issuer, wrong audience, and oversized tokens;
- map subject, service identity, type, and tenant/boundary claims through an
  explicit configured mapping;
- define revocation behavior (short-lived access tokens, introspection, or a
  deny-list) rather than assuming JWTs can be revoked locally;
- expose verifier health, key refresh failures, and issuer changes to
  operations; and
- rotate mTLS certificates through the TLS peer path, using
  `identity.CredentialsFromCertificate`, never a caller-supplied fingerprint.

The built-in HMAC verifier is useful for controlled deployments and tests. Its
secret, issuer, audience, claim names, and required capabilities must be
provided by deployment configuration. Do not use demo principals or a static
development secret outside an isolated development fixture.

Identity authentication does not grant an operation by itself. Loom still
requires explicit policy, boundary membership, resource ACL, and field grants.
