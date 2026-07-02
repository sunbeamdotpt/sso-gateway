CREATE TABLE gateway_sessions (
    session_hash TEXT PRIMARY KEY,
    sub TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    amr TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_gateway_sessions_sub ON gateway_sessions(sub);
CREATE INDEX idx_gateway_sessions_tenant_id ON gateway_sessions(tenant_id);
CREATE INDEX idx_gateway_sessions_expires_at ON gateway_sessions(expires_at)
    WHERE revoked_at IS NULL;
