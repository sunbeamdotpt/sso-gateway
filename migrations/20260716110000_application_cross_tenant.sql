-- Gateway-owned OAuth2 application metadata that does not belong in Hydra.

CREATE TABLE applications (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    public_id TEXT NOT NULL PRIMARY KEY REFERENCES id_mappings(public_id) ON DELETE CASCADE,
    cross_tenant BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_applications_tenant_id ON applications(tenant_id);
