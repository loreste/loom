-- Replace identifiers and role names with deployment configuration. Do not
-- copy example values into an application without reviewing ownership.
ALTER TABLE <tenant_table> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <tenant_table> FORCE ROW LEVEL SECURITY;

CREATE POLICY <tenant_policy> ON <tenant_table>
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- The application role must not own the table and must not have BYPASSRLS.
-- Set app.tenant_id only inside a transaction after Loom resolves the
-- authenticated boundary; reset/rollback it before the connection is reused.
