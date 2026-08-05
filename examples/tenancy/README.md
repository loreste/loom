# Tenant isolation reference

This example is a deployment checklist, not a substitute for a database
security review. Use a configured tenant claim-to-boundary mapping, pass the
boundary to every `app.Call`, and bind the same tenant to the database
transaction. Keep the database role unable to bypass row-level security.

Required adversarial tests:

1. a principal in tenant A cannot read or write tenant B;
2. a missing or conflicting tenant claim is denied;
3. a transaction cannot change its tenant setting after it begins;
4. administrative break-glass access requires a separate operation, approval,
   explicit audit context, and a short-lived credential; and
5. audit records include the authenticated principal and resolved boundary.

Apply [`rls.sql`](rls.sql) to shared tables and use a per-tenant transaction
helper in application code. Loom boundary checks and PostgreSQL RLS should
both be active; neither is sufficient as the sole tenant boundary.
