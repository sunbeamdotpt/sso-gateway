CREATE TABLE saml_nameid_mappings (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    tenant_id TEXT NOT NULL,
    sp_entity_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    name_id TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, sp_entity_id, identity_id)
);

CREATE INDEX idx_saml_nameid_mappings_lookup ON saml_nameid_mappings(tenant_id, sp_entity_id, identity_id);
CREATE INDEX idx_saml_nameid_mappings_nameid ON saml_nameid_mappings(name_id);
