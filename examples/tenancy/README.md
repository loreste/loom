# Tenant isolation reference

This directory is a small reference for shared PostgreSQL tables. It combines
two controls that must agree:

1. Loom resolves a verified tenant claim into the request boundary.
2. PostgreSQL RLS limits rows using the same boundary inside a transaction.

Apply [`rls.sql`](rls.sql) with a migration owner. The application role should
not own the table and must not have `BYPASSRLS`.

Configure `tenancy.NewResolver("tenant_id")` and a database pool with
`RequireTenantContext: true`. Handlers should use `BeginTenant` or
`BeginScoped`, and fixed parameterized queries should include the boundary.
Do not grant free-form `db.query` to ordinary tenant principals.

For environment-driven database wiring, set:

```bash
export LOOM_APP_DB_REQUIRE_TENANT_RLS=true
export LOOM_APP_DB_TENANT_SETTING=app.tenant_id
```

The reference contract is:

- a principal in tenant A cannot read or write tenant B;
- missing or conflicting tenant claims are denied;
- a transaction cannot change its tenant setting after it begins;
- a pool cannot be selected solely from caller input;
- break-glass access is a separate approved operation; and
- audit records contain the principal, resolved boundary, and tenant context.

This example complements, rather than replaces, database roles, RLS,
statement timeouts, connection limits, application policy review, and an
independent security assessment.
