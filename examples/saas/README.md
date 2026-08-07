# Multi-tenant SaaS PostgreSQL RLS reference

This reference combines Loom boundary/tenant resolution with PostgreSQL RLS.
Apply [`../tenancy/rls.sql`](../tenancy/rls.sql) using a migration owner, then
run the application role with:

```sh
export LOOM_APP_DB_URL='postgres://...'
export LOOM_APP_DB_DRIVER=pgx
export LOOM_APP_DB_REQUIRE_TENANT_RLS=true
export LOOM_APP_DB_TENANT_SETTING=app.tenant_id
go run ./examples/saas
```

The application role must not own the protected tables and must not have
`BYPASSRLS`. A verified `tenant_id` claim is resolved into the requested Loom
boundary, and every transaction must use a tenant-bound PostgreSQL executor.
Application policy and boundary checks do not replace RLS. Break-glass access
is a separate approved and audited operation.
