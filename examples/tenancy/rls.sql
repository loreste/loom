-- Reference PostgreSQL RLS migration for a shared tenant table.
-- Run as a migration owner, not as the application role.

CREATE TABLE IF NOT EXISTS tenant_orders (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    customer   TEXT NOT NULL,
    sku        TEXT NOT NULL,
    qty        INTEGER NOT NULL CHECK (qty > 0),
    status     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tenant_orders_tenant_id
    ON tenant_orders (tenant_id);

ALTER TABLE tenant_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_orders FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_orders_isolation ON tenant_orders;
CREATE POLICY tenant_orders_isolation ON tenant_orders
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- The application role must not own this table and must not have BYPASSRLS.
-- Grant only the product-operation privileges required by the application.
