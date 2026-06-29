CREATE TABLE permission_tuples (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    namespace TEXT NOT NULL,
    object TEXT NOT NULL,
    relation TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_permission_tuples_tenant_id ON permission_tuples(tenant_id);
CREATE INDEX idx_permission_tuples_namespace_object ON permission_tuples(namespace, object);
