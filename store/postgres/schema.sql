-- Loom Postgres schema (single-node or HA-ready tables).
-- Apply via store/postgres.Migrate.

CREATE TABLE IF NOT EXISTS loom_schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS loom_approvals (
    token_hash  TEXT PRIMARY KEY,
    principal   TEXT NOT NULL,
    operation   TEXT NOT NULL,
    operation_version TEXT NOT NULL DEFAULT '1',
    boundary    TEXT NOT NULL DEFAULT '',
    max_risk    INT  NOT NULL DEFAULT 3,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed    BOOLEAN NOT NULL DEFAULT FALSE,
    single_use  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_loom_approvals_expires ON loom_approvals (expires_at);
CREATE INDEX IF NOT EXISTS idx_loom_approvals_principal ON loom_approvals (principal);

ALTER TABLE loom_approvals ADD COLUMN IF NOT EXISTS operation_version TEXT NOT NULL DEFAULT '1';

CREATE TABLE IF NOT EXISTS loom_idempotency (
    key         TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    response    JSONB,
    in_flight   BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_loom_idempotency_expires ON loom_idempotency (expires_at);

-- Durable execution status and recovery coordination. Response contains only
-- caller-safe output; raw request input is intentionally not stored here.
CREATE TABLE IF NOT EXISTS loom_executions (
    execution_id          TEXT PRIMARY KEY,
    operation             TEXT NOT NULL,
    operation_version     TEXT NOT NULL,
    principal             TEXT NOT NULL DEFAULT '',
    boundary              TEXT NOT NULL DEFAULT '',
    outcome               TEXT NOT NULL,
    state                 TEXT NOT NULL,
    response              JSONB NOT NULL,
    idempotency_key       TEXT NOT NULL DEFAULT '',
    fingerprint           TEXT NOT NULL DEFAULT '',
    recovery_queued       BOOLEAN NOT NULL DEFAULT FALSE,
    reconciliation_note   TEXT NOT NULL DEFAULT '',
    started_at            TIMESTAMPTZ NOT NULL,
    updated_at            TIMESTAMPTZ NOT NULL,
    revision              BIGINT NOT NULL DEFAULT 1,
    recovery_lease_id     TEXT,
    recovery_lease_owner  TEXT,
    recovery_lease_until  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_loom_executions_recovery
    ON loom_executions (recovery_queued, recovery_lease_until);
CREATE INDEX IF NOT EXISTS idx_loom_executions_updated
    ON loom_executions (updated_at DESC);

-- Archive keeps terminal execution history separate from the hot status table.
-- Applications can export this table to their long-term retention system.
CREATE TABLE IF NOT EXISTS loom_execution_archive (LIKE loom_executions INCLUDING ALL);
CREATE INDEX IF NOT EXISTS idx_loom_execution_archive_updated
    ON loom_execution_archive (updated_at DESC);

CREATE TABLE IF NOT EXISTS loom_audit (
    id          TEXT PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    trace_id    TEXT NOT NULL DEFAULT '',
    decision    TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    step        TEXT NOT NULL DEFAULT '',
    message     TEXT NOT NULL DEFAULT '',
    principal   TEXT NOT NULL DEFAULT '',
    delegator   TEXT NOT NULL DEFAULT '',
    boundary    TEXT NOT NULL DEFAULT '',
    tenant_id   TEXT NOT NULL DEFAULT '',
    operation   TEXT NOT NULL DEFAULT '',
    resource    TEXT NOT NULL DEFAULT '',
    risk        TEXT NOT NULL DEFAULT '',
    input       JSONB,
    metadata    JSONB,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    auth_method TEXT NOT NULL DEFAULT ''
);

ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_loom_audit_ts ON loom_audit (ts DESC);
CREATE INDEX IF NOT EXISTS idx_loom_audit_trace ON loom_audit (trace_id);
CREATE INDEX IF NOT EXISTS idx_loom_audit_principal ON loom_audit (principal);
CREATE INDEX IF NOT EXISTS idx_loom_audit_tenant ON loom_audit (tenant_id);

-- Compliance event fields are additive so existing audit history survives upgrades.
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS schema_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS event_type TEXT NOT NULL DEFAULT 'execution.decision';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS execution_id TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS execution_state TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS execution_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS recovery_queued BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS reconciliation_note TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS protocol_version TEXT NOT NULL DEFAULT '1';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS outcome TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS operation_version TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS resource_type TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS resource_id TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS effects JSONB;
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS input_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS output_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS output_field_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS requested_field_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS boundary_type TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS boundary_parent_type TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS boundary_parent_id TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS idempotency_key_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS idempotency_state TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS approval_state TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS quota_state TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS reliability_warning TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS adapter TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS prior_audit_id TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS prev_event_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE loom_audit ADD COLUMN IF NOT EXISTS event_hash TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_loom_audit_execution ON loom_audit (execution_id);
CREATE INDEX IF NOT EXISTS idx_loom_audit_operation ON loom_audit (operation, operation_version);
CREATE INDEX IF NOT EXISTS idx_loom_audit_decision_reason ON loom_audit (decision, reason);
CREATE INDEX IF NOT EXISTS idx_loom_audit_event_hash ON loom_audit (event_hash);

-- Distributed policy documents (replace semantics by version).
CREATE TABLE IF NOT EXISTS loom_policy (
    id         TEXT PRIMARY KEY,
    version    BIGINT NOT NULL,
    document   JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_loom_policy_version ON loom_policy (version DESC);

-- NOTE: schema version is recorded by store/postgres.Migrate after applying
-- this file; never stamp loom_schema_meta here or the downgrade guard is dead.
