# Tenancy and tenant isolation

Loom treats a tenant as a verified boundary dimension. A request may contain a
boundary ID, but a caller cannot move to another tenant by changing that value
alone. When tenant claim resolution is enabled, the verified claim and request
boundary must agree before policy, resource, quota, approval, or handler work
runs.

Loom provides the application-layer part of tenant isolation. Shared database
tables still need database-layer controls such as PostgreSQL RLS, restricted
roles, tenant-aware transactions, and explicit tenant predicates.

## Configure the tenant claim

Map a verified identity claim into `Identity.Attributes`, then configure a
resolver for the standard attribute:

```go
verifier, err := identity.NewJWTVerifier(identity.JWTConfig{
    Secrets:         managedSecrets,
    Issuer:          issuer,
    Audience:        audience,
    ClaimAttributes: map[string]string{"tenant_id": "tenant_id"},
})
if err != nil {
    return err
}

tenantResolver, err := tenancy.NewResolver("tenant_id")
if err != nil {
    return err
}

a, err := app.New(app.Config{
    IdentityVerifier: verifier,
    TenantResolver:   tenantResolver,
})
```

The resolver rejects a missing or conflicting claim. Do not resolve a tenant
from request metadata, a resource ID, or a client-selected database pool.

## Bind PostgreSQL RLS to the request

Configure the application database with tenant context:

```go
_ = a.OpenDB("main", "pgx", databaseURL, db.Options{
    AllowedTables:        []string{"tenant_orders"},
    RequireTenantContext: true,
    TenantSetting:        "app.tenant_id",
})
```

For environment-driven application database wiring:

```bash
export LOOM_APP_DB_REQUIRE_TENANT_RLS=true
export LOOM_APP_DB_TENANT_SETTING=app.tenant_id
```

Use `BeginTenant` or `BeginScoped` so Loom sets the transaction-local tenant
context before the first product query. A governed query cannot change that
setting, and direct pooled queries are refused for a tenant-bound pool.

The reference migration is [`../examples/tenancy/rls.sql`](../examples/tenancy/rls.sql).
The application role must not own the tables and must not have `BYPASSRLS`.
Product SQL should still include an explicit tenant predicate:

```sql
SELECT id, sku, status
FROM tenant_orders
WHERE tenant_id = $1 AND id = $2
```

## Administrative access

Break-glass access is a separate operation. It should use a short-lived
identity, explicit target tenant, approval, and an audit record. Do not create
tenant-wide access through a wildcard policy or a special request header.

## Required tests

Tenant-aware applications should test that:

- a principal in tenant A cannot read or write tenant B;
- missing or conflicting claims are denied;
- a tenant-bound transaction cannot change its tenant setting;
- a pool is never selected solely from caller input;
- break-glass access requires its separate policy and approval; and
- audit records contain the principal, resolved boundary, and tenant context.

The repository includes resolver, runtime, SQL, transaction, and cross-tenant
tests. PostgreSQL integration tests should additionally run the RLS migration
with a non-owner, non-`BYPASSRLS` role.
