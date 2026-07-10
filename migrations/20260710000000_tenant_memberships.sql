-- Gateway-owned identity traits and per-tenant schema binding. Kratos remains the base
-- identity store ({email} + credentials + sessions); the gateway owns the full trait
-- document and the schema each identity is bound to. identity_id is the gateway public
-- ULID (the same value id_mappings holds for backend = 'kratos'); integrity is enforced
-- at the application level and via the tenant cascade rather than a cross-table FK.
CREATE TABLE tenant_memberships (
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id    TEXT NOT NULL,
    schema_id      TEXT NOT NULL,
    schema_version BIGINT NOT NULL DEFAULT 1,
    traits         JSONB NOT NULL DEFAULT '{}'::jsonb,
    state          TEXT NOT NULL DEFAULT 'active',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, identity_id)
);

CREATE INDEX idx_tenant_memberships_tenant_id ON tenant_memberships(tenant_id);

-- Tenant identity schemas become immutable-by-version-bump: every content change
-- increments version, and memberships pin the schema_version they were written against.
ALTER TABLE tenant_identity_schemas
    ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1;
