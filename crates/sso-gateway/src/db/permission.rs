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

    async fn get(&self, tenant_id: &str, id: &str) -> Result<PermissionTupleRow, DbError>;

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError>;

    async fn list(
        &self,
        tenant_id: &str,
        namespace: Option<&str>,
        object: Option<&str>,
        relation: Option<&str>,
    ) -> Result<Vec<PermissionTupleRow>, DbError>;
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

    async fn get(&self, tenant_id: &str, id: &str) -> Result<PermissionTupleRow, DbError> {
        self.get(tenant_id, id).await
    }

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
        self.delete(tenant_id, id).await
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
}
