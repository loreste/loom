# Tenancy and tenant isolation

Loom treats a tenant as a verified boundary. A request may name a boundary,
but the caller cannot choose a different tenant just by changing that value.
When tenant claim resolution is enabled, the verified identity claim and the
requested boundary must match before policy, resources, quotas, approvals, or
handlers run.

Loom provides the application-layer part of tenant isolation. PostgreSQL RLS,
database roles, and tenant-aware transactions provide the database-layer part.
Use both for shared tables.

## Configure the tenant claim

Map a claim from the production identity verifier into `Identity.Attributes`,
then configure the runtime resolver:

```go
verifier, err := identity.NewJWTVerifier(identity.JWTConfig{
    Secrets:        managedSecrets,
    Issuer:         issuer,
    Audience:       audience,
    ClaimAttributes: map[string]string{"tenant_id": "tenant_id"},
})
if err != nil { return err }

tenantResolver, err := tenancy.NewResolver("tenant_id")
if err != nil { return err }

a, err := app.New(app.Config{
    IdentityVerifier: verifier,
    TenantResolver:   tenantResolver,
})
```

The resolver requires a non-empty request boundary and rejects missing or
conflicting claims. Do not resolve a tenant from request metadata, a resource
ID, or a client-selected database pool.

## Bind PostgreSQL RLS to the transaction

Configure shared tenant pools with `RequireTenantContext`:

```go
_ = a.OpenDB("main", "pgx", databaseURL, db.Options{
    AllowedTables:        []string{"tenant_orders"},
    AllowedBoundaries:    []core.BoundaryID{"tenant-a", "tenant-b"},
    RequireTenantContext: true,
    TenantSetting:        "app.tenant_id",
})
```

For environment-driven application database wiring, the equivalent settings
are:

```bash
export LOOM_APP_DB_REQUIRE_TENANT_RLS=true
export LOOM_APP_DB_TENANT_SETTING=app.tenant_id
```

Handlers use `BeginTenant` or `BeginScoped`. Loom binds the verified boundary
with PostgreSQL transaction-local state before the first product query. A
governed query cannot call `set_config` to change it, and direct pooled queries
are refused for a tenant-bound pool.

The complete migration is in [`examples/tenancy/rls.sql`](../examples/tenancy/rls.sql).
The application database role must not own the tables and must not have
`BYPASSRLS`.

For product operations, also include the tenant column in fixed SQL predicates.
RLS is the database backstop; explicit predicates make intent and query review
clear:

```sql
SELECT id, sku, status
FROM tenant_orders
WHERE tenant_id = $1 AND id = $2
```

## Administrative access

Break-glass access is a separate operation. It must have an explicit policy,
short-lived identity, approval, a declared target tenant, and an audit record.
Do not make tenant-wide access a wildcard policy or a special request header.

## Required tests

Every tenant-aware application should test that:

- tenant A cannot read or write tenant B;
- missing and conflicting claims are denied;
- a tenant-bound transaction cannot change its tenant setting;
- product operations do not select a pool solely from caller input;
- break-glass access requires its separate policy and approval; and
- audit events contain both the resolved boundary and `tenant_id`.

The repository includes resolver, runtime, audit, SQL function, and tenant-bound
pool tests. PostgreSQL integration tests should additionally run the RLS
migration against a non-owner, non-`BYPASSRLS` role.
