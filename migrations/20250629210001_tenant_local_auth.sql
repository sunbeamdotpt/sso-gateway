-- Local credential methods (password / code) per tenant.
-- Looked up by tenant_id after tenant selection, not by HRD domain lookup.

CREATE TABLE tenant_local_auth (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    method TEXT NOT NULL
        CHECK (method IN ('password', 'code')),
    config JSONB NOT NULL DEFAULT '{}',
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenant_local_auth_tenant_id ON tenant_local_auth(tenant_id);

-- One of each local method per tenant.
CREATE UNIQUE INDEX idx_tenant_local_auth_tenant_method_unique
    ON tenant_local_auth(tenant_id, method);
