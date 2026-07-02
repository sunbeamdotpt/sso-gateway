-- Federation identity mappings for JIT SAML provisioning.

CREATE TABLE saml_identity_mappings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL REFERENCES saml_providers(id) ON DELETE CASCADE,
    name_id TEXT NOT NULL,
    identity_public_id TEXT UNIQUE NOT NULL,
    ory_global_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider_id, name_id)
);

CREATE INDEX idx_saml_identity_mappings_tenant_provider ON saml_identity_mappings(tenant_id, provider_id);
CREATE INDEX idx_saml_identity_mappings_identity_public_id ON saml_identity_mappings(identity_public_id);
