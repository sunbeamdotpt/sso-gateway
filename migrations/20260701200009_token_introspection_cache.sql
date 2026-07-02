-- Replace tenant-scoped API keys with an OAuth2 token introspection cache.

DROP TABLE IF EXISTS tenant_api_keys;

CREATE TABLE token_introspection_cache (
    token_hash TEXT PRIMARY KEY,
    active BOOLEAN NOT NULL,
    sub TEXT,
    scope TEXT,
    exp TIMESTAMPTZ,
    cached_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_token_introspection_cache_exp ON token_introspection_cache(exp);
