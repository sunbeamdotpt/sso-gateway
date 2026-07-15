CREATE TABLE permission_namespaces (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    namespace TEXT NOT NULL,
    model JSONB NOT NULL,
    store_id TEXT,
    model_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, namespace)
);

-- Maps every object type defined by a namespace model back to its namespace
-- so tuple and check operations can resolve the owning OpenFGA store.
CREATE TABLE permission_namespace_types (
    tenant_id TEXT NOT NULL,
    type TEXT NOT NULL,
    namespace TEXT NOT NULL,
    PRIMARY KEY (tenant_id, type),
    FOREIGN KEY (tenant_id, namespace)
        REFERENCES permission_namespaces (tenant_id, namespace) ON DELETE CASCADE
);

CREATE INDEX idx_permission_namespace_types_lookup
    ON permission_namespace_types(tenant_id, namespace);

-- Supports keyset pagination of ListRelationTuples.
CREATE INDEX idx_permission_tuples_tenant_created
    ON permission_tuples(tenant_id, created_at DESC, id DESC);
