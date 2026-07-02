-- Custom domain verification for tenants.
-- A domain must be verified via DNS TXT before it can be used in tenant_connections.

CREATE TABLE tenant_domains (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    verification_token TEXT NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenant_domains_tenant_id ON tenant_domains(tenant_id);
CREATE INDEX idx_tenant_domains_domain ON tenant_domains(domain);

-- One tenant can claim a given domain.
CREATE UNIQUE INDEX idx_tenant_domains_domain_unique
    ON tenant_domains(domain);
