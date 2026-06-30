-- Domain-based IdP connections for Home Realm Discovery.
-- Only verified custom domains are allowed; consumer domains cannot be used here.

CREATE TABLE tenant_connections (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connection_type TEXT NOT NULL
        CHECK (connection_type IN ('oidc', 'oauth2', 'saml')),
    domain TEXT NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenant_connections_tenant_id ON tenant_connections(tenant_id);
CREATE INDEX idx_tenant_connections_domain ON tenant_connections(domain);

-- A verified custom domain can only map to one connection.
CREATE UNIQUE INDEX idx_tenant_connections_domain_unique
    ON tenant_connections(domain);
