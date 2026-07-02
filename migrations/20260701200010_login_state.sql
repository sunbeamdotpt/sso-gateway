-- Login state for universal login OIDC/OAuth2/SAML callbacks.

CREATE TABLE login_state (
    state_token TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    connection_type TEXT NOT NULL,
    return_to TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_login_state_expires_at ON login_state(expires_at);
CREATE INDEX idx_login_state_tenant_connection ON login_state(tenant_id, connection_id);
