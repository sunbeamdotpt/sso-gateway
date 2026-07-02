-- SAML hardening: signed-request enforcement, distributed replay cache, IdP keys.

ALTER TABLE saml_providers
    ADD COLUMN authn_requests_signed BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE saml_assertion_ids (
    id TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_saml_assertion_ids_expires_at ON saml_assertion_ids(expires_at);

CREATE TABLE saml_idp_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, key_id)
);

CREATE INDEX idx_saml_idp_keys_tenant_id ON saml_idp_keys(tenant_id);

CREATE TABLE saml_sp_clients (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    acs_url TEXT NOT NULL,
    certificate_pem TEXT,
    authn_requests_signed BOOLEAN NOT NULL DEFAULT false,
    name_id_format TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, entity_id)
);

CREATE INDEX idx_saml_sp_clients_tenant_id ON saml_sp_clients(tenant_id);
CREATE INDEX idx_saml_sp_clients_entity_id ON saml_sp_clients(entity_id);
