# Tenant isolation reference

This directory is a small reference for shared PostgreSQL tables. It shows the
two controls that must agree:

1. Loom resolves a verified tenant claim into the request boundary.
2. PostgreSQL RLS limits rows using the same boundary inside a transaction.

Apply [`rls.sql`](rls.sql) with a migration owner. Run the application with a
role that does not own the table and does not have `BYPASSRLS`.

Configure the application with `tenancy.NewResolver("tenant_id")` and a
PostgreSQL pool using `RequireTenantContext: true`. Product handlers should use
`BeginScoped`/`QueryScoped` and include the boundary in fixed parameterized
queries. Free-form `db.query` should not be granted to end-user principals.

With environment-driven database wiring, set
`LOOM_APP_DB_REQUIRE_TENANT_RLS=true` and use a matching
`LOOM_APP_DB_TENANT_SETTING` such as `app.tenant_id`.

The adversarial contract is:

- a principal in tenant A cannot read or write tenant B;
- a missing or conflicting tenant claim is denied;
- a transaction cannot change its tenant setting after it begins;
- a pool cannot be selected solely from caller input;
- break-glass access is a separate approved operation; and
- audit records contain the principal, resolved boundary, and `tenant_id`.

This reference complements, rather than replaces, database role restrictions,
RLS, statement timeouts, connection limits, and application policy review.
