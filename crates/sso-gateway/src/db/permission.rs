use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct PermissionTupleRow {
    pub id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub object: String,
    pub relation: String,
    pub subject_id: String,
    pub created_at: time::OffsetDateTime,
}

/// Input for a single tuple in a batch create.
#[derive(Debug, Clone)]
pub struct TupleKeyInput {
    pub namespace: String,
    pub object: String,
    pub relation: String,
    pub subject_id: String,
}

#[async_trait]
pub trait PermissionTupleStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<PermissionTupleRow, DbError>;

    async fn create_many(
        &self,
        tenant_id: &str,
        keys: &[TupleKeyInput],
    ) -> Result<Vec<PermissionTupleRow>, DbError>;

    async fn get(&self, tenant_id: &str, id: &str) -> Result<PermissionTupleRow, DbError>;

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError>;

    async fn delete_by_key(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<u64, DbError>;

    async fn delete_by_namespace(&self, tenant_id: &str, namespace: &str) -> Result<u64, DbError>;

    async fn list(
        &self,
        tenant_id: &str,
        namespace: Option<&str>,
        object: Option<&str>,
        relation: Option<&str>,
    ) -> Result<Vec<PermissionTupleRow>, DbError>;

    /// Keyset-paginated list ordered by `(created_at DESC, id DESC)`.
    ///
    /// Returns the page rows plus the total count across all pages. `after`
    /// is the exclusive keyset cursor `(created_at, id)` of the last row of
    /// the previous page.
    async fn list_page(
        &self,
        tenant_id: &str,
        namespace: Option<&str>,
        object: Option<&str>,
        relation: Option<&str>,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<PermissionTupleRow>, i64), DbError>;
}

#[derive(Clone)]
pub struct PgPermissionTupleStore {
    pool: DbPool,
}

impl PgPermissionTupleStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<PermissionTupleRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, PermissionTupleRow>(
            "INSERT INTO permission_tuples \
             (id, tenant_id, namespace, object, relation, subject_id) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, tenant_id, namespace, object, relation, subject_id, created_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(namespace)
        .bind(object)
        .bind(relation)
        .bind(subject_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, id: &str) -> Result<PermissionTupleRow, DbError> {
        let row = sqlx::query_as::<_, PermissionTupleRow>(
            "SELECT id, tenant_id, namespace, object, relation, subject_id, created_at \
             FROM permission_tuples \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::TupleNotFound)
    }

    pub async fn create_many(
        &self,
        tenant_id: &str,
        keys: &[TupleKeyInput],
    ) -> Result<Vec<PermissionTupleRow>, DbError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<String> = keys.iter().map(|_| Ulid::new().to_string()).collect();
        let namespaces: Vec<&str> = keys.iter().map(|k| k.namespace.as_str()).collect();
        let objects: Vec<&str> = keys.iter().map(|k| k.object.as_str()).collect();
        let relations: Vec<&str> = keys.iter().map(|k| k.relation.as_str()).collect();
        let subject_ids: Vec<&str> = keys.iter().map(|k| k.subject_id.as_str()).collect();

        let rows = sqlx::query_as::<_, PermissionTupleRow>(
            "INSERT INTO permission_tuples \
             (id, tenant_id, namespace, object, relation, subject_id) \
             SELECT t.id, $1, t.namespace, t.object, t.relation, t.subject_id \
             FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) \
                  AS t(id, namespace, object, relation, subject_id) \
             RETURNING id, tenant_id, namespace, object, relation, subject_id, created_at",
        )
        .bind(tenant_id)
        .bind(&ids)
        .bind(&namespaces)
        .bind(&objects)
        .bind(&relations)
        .bind(&subject_ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn delete_by_key(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<u64, DbError> {
        let result = sqlx::query(
            "DELETE FROM permission_tuples \
             WHERE tenant_id = $1 AND namespace = $2 AND object = $3 \
               AND relation = $4 AND subject_id = $5",
        )
        .bind(tenant_id)
        .bind(namespace)
        .bind(object)
        .bind(relation)
        .bind(subject_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn delete_by_namespace(
        &self,
        tenant_id: &str,
        namespace: &str,
    ) -> Result<u64, DbError> {
        let result =
            sqlx::query("DELETE FROM permission_tuples WHERE tenant_id = $1 AND namespace = $2")
                .bind(tenant_id)
                .bind(namespace)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected())
    }

    pub async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
        let result = sqlx::query("DELETE FROM permission_tuples WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::TupleNotFound);
        }
        Ok(())
    }

    pub async fn list(
        &self,
        tenant_id: &str,
        namespace: Option<&str>,
        object: Option<&str>,
        relation: Option<&str>,
    ) -> Result<Vec<PermissionTupleRow>, DbError> {
        let mut query = String::from(
            "SELECT id, tenant_id, namespace, object, relation, subject_id, created_at \
             FROM permission_tuples \
             WHERE tenant_id = $1",
        );
        let mut param_idx = 2;
        if namespace.is_some() {
            query.push_str(&format!(" AND namespace = ${param_idx}"));
            param_idx += 1;
        }
        if object.is_some() {
            query.push_str(&format!(" AND object = ${param_idx}"));
            param_idx += 1;
        }
        if relation.is_some() {
            query.push_str(&format!(" AND relation = ${param_idx}"));
        }
        query.push_str(" ORDER BY created_at DESC");

        let mut q = sqlx::query_as::<_, PermissionTupleRow>(&query).bind(tenant_id);
        if let Some(namespace) = namespace {
            q = q.bind(namespace);
        }
        if let Some(object) = object {
            q = q.bind(object);
        }
        if let Some(relation) = relation {
            q = q.bind(relation);
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows)
    }

    pub async fn list_page(
        &self,
        tenant_id: &str,
        namespace: Option<&str>,
        object: Option<&str>,
        relation: Option<&str>,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<PermissionTupleRow>, i64), DbError> {
        let mut filters = String::from("tenant_id = $1");
        let mut param_idx = 2;
        if namespace.is_some() {
            filters.push_str(&format!(" AND namespace = ${param_idx}"));
            param_idx += 1;
        }
        if object.is_some() {
            filters.push_str(&format!(" AND object = ${param_idx}"));
            param_idx += 1;
        }
        if relation.is_some() {
            filters.push_str(&format!(" AND relation = ${param_idx}"));
            param_idx += 1;
        }

        let count_query = format!("SELECT COUNT(*) FROM permission_tuples WHERE {filters}");
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(namespace) = namespace {
            count_q = count_q.bind(namespace);
        }
        if let Some(object) = object {
            count_q = count_q.bind(object);
        }
        if let Some(relation) = relation {
            count_q = count_q.bind(relation);
        }
        let total = count_q.fetch_one(&self.pool).await?;

        let mut query = format!(
            "SELECT id, tenant_id, namespace, object, relation, subject_id, created_at \
             FROM permission_tuples WHERE {filters}"
        );
        if after.is_some() {
            query.push_str(&format!(
                " AND (created_at, id) < (${param_idx}, ${})",
                param_idx + 1
            ));
            param_idx += 2;
        }
        query.push_str(&format!(
            " ORDER BY created_at DESC, id DESC LIMIT ${param_idx}"
        ));

        let mut q = sqlx::query_as::<_, PermissionTupleRow>(&query).bind(tenant_id);
        if let Some(namespace) = namespace {
            q = q.bind(namespace);
        }
        if let Some(object) = object {
            q = q.bind(object);
        }
        if let Some(relation) = relation {
            q = q.bind(relation);
        }
        if let Some((created_at, id)) = after {
            q = q.bind(created_at).bind(id);
        }
        q = q.bind(i64::from(limit));
        let rows = q.fetch_all(&self.pool).await?;
        Ok((rows, total))
    }
}

#[async_trait]
impl PermissionTupleStore for PgPermissionTupleStore {
    async fn create(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<PermissionTupleRow, DbError> {
        self.create(tenant_id, namespace, object, relation, subject_id)
            .await
    }

    async fn create_many(
        &self,
        tenant_id: &str,
        keys: &[TupleKeyInput],
    ) -> Result<Vec<PermissionTupleRow>, DbError> {
        self.create_many(tenant_id, keys).await
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<PermissionTupleRow, DbError> {
        self.get(tenant_id, id).await
    }

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
        self.delete(tenant_id, id).await
    }

    async fn delete_by_key(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<u64, DbError> {
        self.delete_by_key(tenant_id, namespace, object, relation, subject_id)
            .await
    }

    async fn delete_by_namespace(&self, tenant_id: &str, namespace: &str) -> Result<u64, DbError> {
        self.delete_by_namespace(tenant_id, namespace).await
    }

    async fn list(
        &self,
        tenant_id: &str,
        namespace: Option<&str>,
        object: Option<&str>,
        relation: Option<&str>,
    ) -> Result<Vec<PermissionTupleRow>, DbError> {
        self.list(tenant_id, namespace, object, relation).await
    }

    async fn list_page(
        &self,
        tenant_id: &str,
        namespace: Option<&str>,
        object: Option<&str>,
        relation: Option<&str>,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<PermissionTupleRow>, i64), DbError> {
        self.list_page(tenant_id, namespace, object, relation, limit, after)
            .await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for PermissionTupleRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            namespace: row.try_get("namespace")?,
            object: row.try_get("object")?,
            relation: row.try_get("relation")?,
            subject_id: row.try_get("subject_id")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    async fn store() -> PgPermissionTupleStore {
        PgPermissionTupleStore::new(postgres_pool().await)
    }

    #[test]
    fn permission_tuple_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = PermissionTupleRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            namespace: "ns".to_string(),
            object: "obj".to_string(),
            relation: "rel".to_string(),
            subject_id: "sub".to_string(),
            created_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.namespace, "ns");
    }

    #[tokio::test]
    async fn tuple_lifecycle_and_filters() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let created = store
            .create(&tenant, "app", "doc-1", "owner", "user-1")
            .await
            .unwrap();
        assert_eq!(created.namespace, "app");
        assert_eq!(created.object, "doc-1");
        assert_eq!(created.relation, "owner");
        assert_eq!(created.subject_id, "user-1");

        let found = store.get(&tenant, &created.id).await.unwrap();
        assert_eq!(found.id, created.id);

        let all = store.list(&tenant, None, None, None).await.unwrap();
        assert_eq!(all.len(), 1);

        let by_ns = store.list(&tenant, Some("app"), None, None).await.unwrap();
        assert_eq!(by_ns.len(), 1);

        let by_obj = store
            .list(&tenant, None, Some("doc-1"), None)
            .await
            .unwrap();
        assert_eq!(by_obj.len(), 1);

        let by_rel = store
            .list(&tenant, None, None, Some("owner"))
            .await
            .unwrap();
        assert_eq!(by_rel.len(), 1);

        let combined = store
            .list(&tenant, Some("app"), Some("doc-1"), Some("owner"))
            .await
            .unwrap();
        assert_eq!(combined.len(), 1);

        let no_match = store
            .list(&tenant, Some("other"), None, None)
            .await
            .unwrap();
        assert!(no_match.is_empty());

        store.delete(&tenant, &created.id).await.unwrap();
        assert!(matches!(
            store.get(&tenant, &created.id).await.unwrap_err(),
            DbError::TupleNotFound
        ));
    }

    #[tokio::test]
    async fn tuple_not_found_cases() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        assert!(matches!(
            store.get(&tenant, "missing").await.unwrap_err(),
            DbError::TupleNotFound
        ));
        assert!(matches!(
            store.delete(&tenant, "missing").await.unwrap_err(),
            DbError::TupleNotFound
        ));
        assert!(
            store
                .list(&tenant, None, None, None)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn trait_object_methods() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn PermissionTupleStore> = Arc::new(PgPermissionTupleStore::new(pool));

        let created = store
            .create(&tenant, "ns", "obj", "rel", "sub")
            .await
            .unwrap();
        assert!(store.get(&tenant, &created.id).await.is_ok());
        assert_eq!(
            store.list(&tenant, None, None, None).await.unwrap().len(),
            1
        );
        assert!(store.delete(&tenant, &created.id).await.is_ok());
    }

    fn key(namespace: &str, object: &str, relation: &str, subject_id: &str) -> TupleKeyInput {
        TupleKeyInput {
            namespace: namespace.into(),
            object: object.into(),
            relation: relation.into(),
            subject_id: subject_id.into(),
        }
    }

    #[tokio::test]
    async fn create_many_and_delete_by_key() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        assert!(store.create_many(&tenant, &[]).await.unwrap().is_empty());

        let keys = vec![
            key("app", "doc-1", "reader", "user-1"),
            key("app", "doc-1", "reader", "user-2"),
            key("app", "doc-2", "owner", "user-1"),
        ];
        let rows = store.create_many(&tenant, &keys).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r.tenant_id == tenant));

        let deleted = store
            .delete_by_key(&tenant, "app", "doc-1", "reader", "user-1")
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        let remaining = store.list(&tenant, None, None, None).await.unwrap();
        assert_eq!(remaining.len(), 2);

        // Deleting an unknown key affects no rows but is not an error.
        let deleted = store
            .delete_by_key(&tenant, "app", "doc-9", "reader", "user-9")
            .await
            .unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn delete_by_namespace_removes_only_that_namespace() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        store
            .create_many(
                &tenant,
                &[
                    key("app", "doc-1", "reader", "user-1"),
                    key("app", "doc-2", "reader", "user-1"),
                    key("other", "doc-1", "reader", "user-1"),
                ],
            )
            .await
            .unwrap();

        let deleted = store.delete_by_namespace(&tenant, "app").await.unwrap();
        assert_eq!(deleted, 2);

        let remaining = store.list(&tenant, None, None, None).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].namespace, "other");
    }

    #[tokio::test]
    async fn list_page_paginates_with_keyset_and_total() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let keys: Vec<TupleKeyInput> = (0..5)
            .map(|i| key("app", &format!("doc-{i}"), "reader", "user-1"))
            .collect();
        store.create_many(&tenant, &keys).await.unwrap();

        let (page1, total) = store
            .list_page(&tenant, None, None, None, 2, None)
            .await
            .unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(total, 5);

        let cursor = page1.last().map(|r| (r.created_at, r.id.clone())).unwrap();
        let (page2, total) = store
            .list_page(&tenant, None, None, None, 2, Some(cursor))
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(total, 5);

        let cursor = page2.last().map(|r| (r.created_at, r.id.clone())).unwrap();
        let (page3, _) = store
            .list_page(&tenant, None, None, None, 2, Some(cursor))
            .await
            .unwrap();
        assert_eq!(page3.len(), 1);

        // Pages are disjoint and ordered.
        let mut seen: Vec<String> = page1
            .iter()
            .chain(page2.iter())
            .chain(page3.iter())
            .map(|r| r.object.clone())
            .collect();
        seen.dedup();
        assert_eq!(seen.len(), 5);

        // Filters compose with pagination.
        let (filtered, total) = store
            .list_page(&tenant, Some("app"), Some("doc-3"), None, 10, None)
            .await
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(total, 1);
    }
}
