use serde_json::Value;
use sqlx::Row;

use super::{DbError, DbPool};

/// A registered permission namespace and its current model.
///
/// `store_id`/`model_id` are `None` on backends that do not provision stores
/// (Keto); the row then acts as pure metadata for list/get.
#[derive(Debug, Clone)]
pub struct PermissionNamespaceRow {
    pub tenant_id: String,
    pub namespace: String,
    pub model: Value,
    /// Relation-bearing (object-capable) types defined by the model, resolved
    /// from the type index. Bare subject types (e.g. `user`) are not indexed.
    pub types: Vec<String>,
    pub store_id: Option<String>,
    pub model_id: Option<String>,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

/// Extract the sorted names of types that define at least one relation.
///
/// Only relation-bearing types can own objects (and therefore tuples), so the
/// per-tenant type index and its uniqueness constraint cover just these.
/// Bare subject types (virtually every model declares a bare `user`) may be
/// shared by any number of namespaces of the same tenant.
pub fn relation_bearing_type_names(model: &Value) -> Vec<String> {
    let mut types: Vec<String> = match model.get("type_definitions").and_then(|v| v.as_array()) {
        Some(defs) => defs
            .iter()
            .filter(|def| {
                def.get("relations")
                    .and_then(|r| r.as_object())
                    .is_some_and(|relations| !relations.is_empty())
            })
            .filter_map(|def| def.get("type").and_then(|t| t.as_str()).map(String::from))
            .collect(),
        None => Vec::new(),
    };
    types.sort();
    types
}

#[derive(Clone)]
pub struct PgPermissionNamespaceStore {
    pool: DbPool,
}

const SELECT_ROW: &str = "SELECT n.tenant_id, n.namespace, n.model, n.store_id, n.model_id, \
     n.created_at, n.updated_at, \
     COALESCE(array_agg(t.type ORDER BY t.type) FILTER (WHERE t.type IS NOT NULL), '{}') AS types \
     FROM permission_namespaces n \
     LEFT JOIN permission_namespace_types t \
       ON t.tenant_id = n.tenant_id AND t.namespace = n.namespace";

impl PgPermissionNamespaceStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn get(
        &self,
        tenant_id: &str,
        namespace: &str,
    ) -> Result<Option<PermissionNamespaceRow>, DbError> {
        let row = sqlx::query_as::<_, PermissionNamespaceRow>(&format!(
            "{SELECT_ROW} WHERE n.tenant_id = $1 AND n.namespace = $2 \
             GROUP BY n.tenant_id, n.namespace"
        ))
        .bind(tenant_id)
        .bind(namespace)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Resolve the namespace that owns an object type.
    ///
    /// Falls back to treating the type as a namespace name so namespaces
    /// registered before the type index existed (or without indexed types)
    /// keep resolving.
    pub async fn get_by_type(
        &self,
        tenant_id: &str,
        object_type: &str,
    ) -> Result<Option<PermissionNamespaceRow>, DbError> {
        let row = sqlx::query_as::<_, PermissionNamespaceRow>(&format!(
            "{SELECT_ROW} WHERE n.tenant_id = $1 AND n.namespace = ( \
                 SELECT namespace FROM permission_namespace_types \
                 WHERE tenant_id = $1 AND type = $2 \
             ) GROUP BY n.tenant_id, n.namespace"
        ))
        .bind(tenant_id)
        .bind(object_type)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => Ok(Some(row)),
            None => self.get(tenant_id, object_type).await,
        }
    }

    pub async fn list(&self, tenant_id: &str) -> Result<Vec<PermissionNamespaceRow>, DbError> {
        let rows = sqlx::query_as::<_, PermissionNamespaceRow>(&format!(
            "{SELECT_ROW} WHERE n.tenant_id = $1 \
             GROUP BY n.tenant_id, n.namespace ORDER BY n.namespace ASC"
        ))
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Insert or update a namespace row and sync its type index.
    ///
    /// The type index is derived from the model: only relation-bearing
    /// (object-capable) types are indexed and checked for conflicts; bare
    /// subject types such as `user` may be declared by many namespaces.
    /// `store_id`/`model_id` of `None` leave any previously provisioned ids
    /// untouched (COALESCE merge). Fails with
    /// `DbError::NamespaceTypeConflict` when a relation-bearing type is owned
    /// by another namespace of the same tenant.
    pub async fn upsert(
        &self,
        tenant_id: &str,
        namespace: &str,
        model: &Value,
        store_id: Option<&str>,
        model_id: Option<&str>,
    ) -> Result<PermissionNamespaceRow, DbError> {
        let index_types = relation_bearing_type_names(model);
        let mut tx = self.pool.begin().await?;

        let conflicts: Vec<String> = sqlx::query_scalar(
            "SELECT type FROM permission_namespace_types \
             WHERE tenant_id = $1 AND type = ANY($2) AND namespace != $3",
        )
        .bind(tenant_id)
        .bind(&index_types)
        .bind(namespace)
        .fetch_all(&mut *tx)
        .await?;
        if let Some(conflict) = conflicts.into_iter().next() {
            return Err(DbError::NamespaceTypeConflict(conflict));
        }

        sqlx::query(
            "INSERT INTO permission_namespaces (tenant_id, namespace, model, store_id, model_id) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (tenant_id, namespace) DO UPDATE SET \
                 model = EXCLUDED.model, \
                 store_id = COALESCE(EXCLUDED.store_id, permission_namespaces.store_id), \
                 model_id = COALESCE(EXCLUDED.model_id, permission_namespaces.model_id), \
                 updated_at = NOW()",
        )
        .bind(tenant_id)
        .bind(namespace)
        .bind(model)
        .bind(store_id)
        .bind(model_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "DELETE FROM permission_namespace_types \
             WHERE tenant_id = $1 AND namespace = $2 AND NOT (type = ANY($3))",
        )
        .bind(tenant_id)
        .bind(namespace)
        .bind(&index_types)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO permission_namespace_types (tenant_id, type, namespace) \
             SELECT $1, unnest($3::text[]), $2 \
             ON CONFLICT (tenant_id, type) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(namespace)
        .bind(&index_types)
        .execute(&mut *tx)
        .await?;

        let row = sqlx::query_as::<_, PermissionNamespaceRow>(&format!(
            "{SELECT_ROW} WHERE n.tenant_id = $1 AND n.namespace = $2 \
             GROUP BY n.tenant_id, n.namespace"
        ))
        .bind(tenant_id)
        .bind(namespace)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(row)
    }

    pub async fn delete(&self, tenant_id: &str, namespace: &str) -> Result<(), DbError> {
        // The type index rows are removed by the ON DELETE CASCADE foreign key.
        sqlx::query("DELETE FROM permission_namespaces WHERE tenant_id = $1 AND namespace = $2")
            .bind(tenant_id)
            .bind(namespace)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for PermissionNamespaceRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            tenant_id: row.try_get("tenant_id")?,
            namespace: row.try_get("namespace")?,
            model: row.try_get("model")?,
            types: row.try_get("types")?,
            store_id: row.try_get("store_id")?,
            model_id: row.try_get("model_id")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ulid::Ulid;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    async fn store_and_tenant() -> (PgPermissionNamespaceStore, DbPool, String) {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        (PgPermissionNamespaceStore::new(pool.clone()), pool, tenant)
    }

    /// A model whose non-`user` types are relation-bearing (a single `viewer`
    /// relation), mirroring the shape real models take.
    fn model(types: &[&str]) -> Value {
        let defs: Vec<Value> = types
            .iter()
            .map(|t| {
                if *t == "user" {
                    json!({ "type": "user" })
                } else {
                    json!({
                        "type": t,
                        "relations": { "viewer": { "this": {} } },
                        "metadata": {
                            "relations": {
                                "viewer": { "directly_related_user_types": [{ "type": "user" }] }
                            }
                        }
                    })
                }
            })
            .collect();
        json!({ "schema_version": "1.1", "type_definitions": defs })
    }

    /// A model of bare (relation-less) types only.
    fn bare_model(types: &[&str]) -> Value {
        let defs: Vec<Value> = types.iter().map(|t| json!({ "type": t })).collect();
        json!({ "schema_version": "1.1", "type_definitions": defs })
    }

    #[test]
    fn relation_bearing_type_names_filters_bare_types() {
        let model = model(&["user", "KanbanProject", "KanbanCard"]);
        assert_eq!(
            relation_bearing_type_names(&model),
            vec!["KanbanCard".to_string(), "KanbanProject".to_string()]
        );
        assert!(relation_bearing_type_names(&bare_model(&["user"])).is_empty());
        // An explicitly empty relations object does not count either.
        let empty_relations = json!({
            "schema_version": "1.1",
            "type_definitions": [{ "type": "thing", "relations": {} }]
        });
        assert!(relation_bearing_type_names(&empty_relations).is_empty());
        assert!(relation_bearing_type_names(&json!({})).is_empty());
    }

    #[tokio::test]
    async fn upsert_get_list_delete_round_trip() {
        let (store, _pool, tenant) = store_and_tenant().await;

        assert!(store.get(&tenant, "kanban").await.unwrap().is_none());

        let row = store
            .upsert(
                &tenant,
                "kanban",
                &model(&["user", "KanbanProject"]),
                Some("store-1"),
                Some("model-1"),
            )
            .await
            .unwrap();
        assert_eq!(row.store_id.as_deref(), Some("store-1"));
        assert_eq!(row.model_id.as_deref(), Some("model-1"));
        // Only relation-bearing types are indexed; bare `user` is not.
        assert_eq!(row.types, vec!["KanbanProject"]);

        // Merge semantics: model + types move forward, ids are preserved when
        // the caller passes None (metadata-only path used on Keto).
        let updated = store
            .upsert(
                &tenant,
                "kanban",
                &model(&["user", "KanbanProject", "KanbanCard"]),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(updated.store_id.as_deref(), Some("store-1"));
        assert_eq!(updated.model_id.as_deref(), Some("model-1"));
        assert_eq!(updated.types, vec!["KanbanCard", "KanbanProject"]);
        assert!(updated.updated_at >= updated.created_at);

        // Provisioning later fills the ids.
        let provisioned = store
            .upsert(
                &tenant,
                "kanban",
                &model(&["user", "KanbanProject", "KanbanCard"]),
                Some("store-1"),
                Some("model-2"),
            )
            .await
            .unwrap();
        assert_eq!(provisioned.model_id.as_deref(), Some("model-2"));

        let all = store.list(&tenant).await.unwrap();
        assert_eq!(all.len(), 1);

        store.delete(&tenant, "kanban").await.unwrap();
        assert!(store.get(&tenant, "kanban").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_by_type_resolves_index_and_falls_back_to_namespace() {
        let (store, _pool, tenant) = store_and_tenant().await;
        store
            .upsert(
                &tenant,
                "kanban",
                &model(&["user", "KanbanProject", "KanbanCard"]),
                Some("store-1"),
                Some("model-1"),
            )
            .await
            .unwrap();
        // A second namespace that does not index a type named after itself.
        store
            .upsert(
                &tenant,
                "legacy",
                &model(&["legacy_thing"]),
                Some("store-2"),
                Some("model-3"),
            )
            .await
            .unwrap();

        let by_type = store.get_by_type(&tenant, "KanbanCard").await.unwrap().unwrap();
        assert_eq!(by_type.namespace, "kanban");

        // Fallback: "legacy" is not in the type index but is a namespace name.
        let fallback = store.get_by_type(&tenant, "legacy").await.unwrap().unwrap();
        assert_eq!(fallback.namespace, "legacy");

        assert!(store.get_by_type(&tenant, "unknown").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn upsert_rejects_relation_bearing_type_owned_by_other_namespace() {
        let (store, _pool, tenant) = store_and_tenant().await;
        store
            .upsert(&tenant, "one", &model(&["Shared"]), None, None)
            .await
            .unwrap();

        let err = store
            .upsert(&tenant, "two", &model(&["Shared"]), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::NamespaceTypeConflict(t) if t == "Shared"));

        // Same namespace may re-register its own type.
        store
            .upsert(&tenant, "one", &model(&["Shared"]), None, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upsert_allows_namespaces_sharing_bare_types() {
        let (store, _pool, tenant) = store_and_tenant().await;
        // Virtually every OpenFGA model declares a bare `user` type; that must
        // not block a second namespace of the same tenant (SSO-030).
        store
            .upsert(
                &tenant,
                "scim_group",
                &model(&["user", "scim_group"]),
                Some("store-1"),
                Some("model-1"),
            )
            .await
            .unwrap();
        let row = store
            .upsert(
                &tenant,
                "entitlements",
                &model(&["user", "entitlements"]),
                Some("store-2"),
                Some("model-2"),
            )
            .await
            .unwrap();
        assert_eq!(row.types, vec!["entitlements"]);

        // Pure bare-type models index nothing and never conflict.
        store
            .upsert(&tenant, "bare", &bare_model(&["user", "group"]), None, None)
            .await
            .unwrap();
        let bare = store.get(&tenant, "bare").await.unwrap().unwrap();
        assert!(bare.types.is_empty());
    }

    #[tokio::test]
    async fn re_upsert_removes_stale_index_rows() {
        let (store, pool, tenant) = store_and_tenant().await;
        store
            .upsert(
                &tenant,
                "kanban",
                &model(&["user", "KanbanProject", "KanbanCard"]),
                None,
                None,
            )
            .await
            .unwrap();

        // Re-upsert with a model that dropped KanbanCard and made
        // KanbanProject bare: both must leave the index.
        store
            .upsert(
                &tenant,
                "kanban",
                &json!({
                    "schema_version": "1.1",
                    "type_definitions": [
                        { "type": "user" },
                        { "type": "KanbanProject" },
                        {
                            "type": "KanbanBoard",
                            "relations": { "viewer": { "this": {} } },
                        }
                    ]
                }),
                None,
                None,
            )
            .await
            .unwrap();

        let indexed: Vec<String> = sqlx::query_scalar(
            "SELECT type FROM permission_namespace_types WHERE tenant_id = $1 ORDER BY type",
        )
        .bind(&tenant)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(indexed, vec!["KanbanBoard".to_string()]);
    }

    #[tokio::test]
    async fn delete_cascades_type_index() {
        let (store, pool, tenant) = store_and_tenant().await;
        store
            .upsert(
                &tenant,
                "kanban",
                &model(&["KanbanCard"]),
                Some("store-1"),
                Some("model-1"),
            )
            .await
            .unwrap();

        store.delete(&tenant, "kanban").await.unwrap();
        let indexed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM permission_namespace_types WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(indexed, 0);
    }
}
