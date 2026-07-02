-- Inbound SAML AuthnRequest replay cache for the SAML IdP endpoint.
-- Request IDs are stored with a TTL and rejected on duplicate ingestion.

CREATE TABLE saml_inbound_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_saml_inbound_requests_expires_at ON saml_inbound_requests(expires_at);
CREATE INDEX idx_saml_inbound_requests_tenant_id ON saml_inbound_requests(tenant_id);
