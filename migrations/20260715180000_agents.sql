-- Gateway-owned agent (non-human) identities. Agents are deliberately not
-- Kratos identities: Kratos models interactive human flows, while agents
-- authenticate with OAuth2 client_credentials against a Hydra client linked
-- via id_mappings (backend = 'hydra', public_id = agents.id). tenant_id is
-- the agent's home tenant; cross-tenant membership is future work.
CREATE TABLE agents (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_identity_id TEXT,
    name              TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'active',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_tenant_created
    ON agents(tenant_id, created_at DESC, id DESC);

-- Pre-authorized delegation grants: user_identity_id allows agent_id to mint
-- on-behalf-of tokens scoped to the listed scopes until expires_at. Revoking
-- the grant (revoked_at) is the "big red button": act-token introspection
-- re-checks the grant, so revocation takes effect immediately.
CREATE TABLE agent_delegations (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id          TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_identity_id  TEXT NOT NULL,
    scopes            TEXT[] NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    revoked_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_delegations_agent
    ON agent_delegations(tenant_id, agent_id, created_at DESC, id DESC);

CREATE INDEX idx_agent_delegations_user
    ON agent_delegations(tenant_id, user_identity_id, created_at DESC, id DESC);

-- Opaque on-behalf-of access tokens minted against a delegation. Only the
-- SHA-256 hash of the bearer token is stored; the raw token is returned to
-- the agent exactly once at mint time.
CREATE TABLE agent_act_tokens (
    token_hash        TEXT PRIMARY KEY,
    delegation_id     TEXT NOT NULL REFERENCES agent_delegations(id) ON DELETE CASCADE,
    tenant_id         TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    user_identity_id  TEXT NOT NULL,
    scopes            TEXT[] NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
