-- Opaque mappings for short-lived protocol tokens (Kratos flows/sessions/tokens,
-- Hydra consent/login/logout challenges). Public ULIDs are exposed to callers;
-- backend tokens are stored here with an explicit expiration.

CREATE TABLE transient_token_mappings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    backend TEXT NOT NULL CHECK (backend IN ('hydra', 'kratos')),
    token_type TEXT NOT NULL,
    public_token TEXT UNIQUE NOT NULL,
    ory_token TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, backend, token_type, ory_token)
);

CREATE INDEX idx_transient_token_public
    ON transient_token_mappings(tenant_id, backend, token_type, public_token);
CREATE INDEX idx_transient_token_ory
    ON transient_token_mappings(tenant_id, backend, token_type, ory_token);
CREATE INDEX idx_transient_token_expires
    ON transient_token_mappings(expires_at);
