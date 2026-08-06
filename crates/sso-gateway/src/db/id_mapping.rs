use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct IdMappingRow {
    pub id: String,
    pub tenant_id: String,
    pub backend: String,
    pub public_id: String,
    pub ory_global_id: String,
    pub created_at: time::OffsetDateTime,
}

#[async_trait]
pub trait IdMappingStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
        ory_global_id: &str,
    ) -> Result<IdMappingRow, DbError>;

    async fn get_ory_id(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
    ) -> Result<String, DbError>;

    /// Resolve a gateway public id to the backend Ory global id.
    async fn get_ory_id_by_public_id(
        &self,
        backend: &str,
        public_id: &str,
    ) -> Result<String, DbError> {
        let _ = (backend, public_id);
        Err(DbError::MappingNotFound)
    }

    async fn get_public_id(
        &self,
        tenant_id: &str,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError>;

    /// Resolve a backend Ory global id to the gateway public id.
    async fn get_public_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError> {
        let _ = (backend, ory_global_id);
        Err(DbError::MappingNotFound)
    }

    async fn delete(&self, tenant_id: &str, backend: &str, public_id: &str) -> Result<(), DbError>;

    async fn list_public_ids(&self, tenant_id: &str, backend: &str)
    -> Result<Vec<String>, DbError>;

    /// List full mapping rows (including `created_at`) for a tenant+backend.
    ///
    /// Used by the DCR garbage collector, which needs registration ages, not
    /// just ids. Stores that do not track full rows may keep the default.
    async fn list_mappings(
        &self,
        tenant_id: &str,
        backend: &str,
    ) -> Result<Vec<IdMappingRow>, DbError> {
        let _ = (tenant_id, backend);
        Err(DbError::MappingNotFound)
    }

    /// Find the tenant that owns a given Ory global id for a backend.
    async fn get_tenant_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<Option<String>, DbError>;

    /// Move a mapping row to a different tenant (DCR first-use re-home,
    /// SSO-039). `public_id` is globally unique, so this is a plain row
    /// update keyed by backend + public id. Stores that cannot re-home keep
    /// the default.
    async fn update_tenant(
        &self,
        backend: &str,
        public_id: &str,
        new_tenant_id: &str,
    ) -> Result<(), DbError> {
        let _ = (backend, public_id, new_tenant_id);
        Err(DbError::MappingNotFound)
    }
}

#[derive(Clone)]
pub struct PgIdMappingStore {
    pool: DbPool,
}

impl PgIdMappingStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
        ory_global_id: &str,
    ) -> Result<IdMappingRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, IdMappingRow>(
            "INSERT INTO id_mappings (id, tenant_id, backend, public_id, ory_global_id) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, tenant_id, backend, public_id, ory_global_id, created_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(backend)
        .bind(public_id)
        .bind(ory_global_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_ory_id(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
    ) -> Result<String, DbError> {
        let id: Option<String> = sqlx::query_scalar(
            "SELECT ory_global_id FROM id_mappings \
             WHERE tenant_id = $1 AND backend = $2 AND public_id = $3",
        )
        .bind(tenant_id)
        .bind(backend)
        .bind(public_id)
        .fetch_optional(&self.pool)
        .await?;
        id.ok_or(DbError::MappingNotFound)
    }

    pub async fn get_public_id(
        &self,
        tenant_id: &str,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError> {
        let id: Option<String> = sqlx::query_scalar(
            "SELECT public_id FROM id_mappings \
             WHERE tenant_id = $1 AND backend = $2 AND ory_global_id = $3",
        )
        .bind(tenant_id)
        .bind(backend)
        .bind(ory_global_id)
        .fetch_optional(&self.pool)
        .await?;
        id.ok_or(DbError::MappingNotFound)
    }

    pub async fn get_public_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError> {
        let id: Option<String> = sqlx::query_scalar(
            "SELECT public_id FROM id_mappings \
             WHERE backend = $1 AND ory_global_id = $2 LIMIT 1",
        )
        .bind(backend)
        .bind(ory_global_id)
        .fetch_optional(&self.pool)
        .await?;
        id.ok_or(DbError::MappingNotFound)
    }

    pub async fn delete(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
    ) -> Result<(), DbError> {
        let result = sqlx::query(
            "DELETE FROM id_mappings WHERE tenant_id = $1 AND backend = $2 AND public_id = $3",
        )
        .bind(tenant_id)
        .bind(backend)
        .bind(public_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::MappingNotFound);
        }
        Ok(())
    }

    pub async fn list_public_ids(
        &self,
        tenant_id: &str,
        backend: &str,
    ) -> Result<Vec<String>, DbError> {
        let ids = sqlx::query_scalar(
            "SELECT public_id FROM id_mappings \
             WHERE tenant_id = $1 AND backend = $2 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .bind(backend)
        .fetch_all(&self.pool)
        .await?;
        Ok(ids)
    }

    pub async fn list_mappings(
        &self,
        tenant_id: &str,
        backend: &str,
    ) -> Result<Vec<IdMappingRow>, DbError> {
        let rows = sqlx::query_as::<_, IdMappingRow>(
            "SELECT id, tenant_id, backend, public_id, ory_global_id, created_at \
             FROM id_mappings \
             WHERE tenant_id = $1 AND backend = $2 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .bind(backend)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn get_tenant_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<Option<String>, DbError> {
        let tenant_id: Option<String> = sqlx::query_scalar(
            "SELECT tenant_id FROM id_mappings \
             WHERE backend = $1 AND ory_global_id = $2 LIMIT 1",
        )
        .bind(backend)
        .bind(ory_global_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(tenant_id)
    }

    pub async fn get_ory_id_by_public_id(
        &self,
        backend: &str,
        public_id: &str,
    ) -> Result<String, DbError> {
        let ory_id: Option<String> = sqlx::query_scalar(
            "SELECT ory_global_id FROM id_mappings \
             WHERE backend = $1 AND public_id = $2 LIMIT 1",
        )
        .bind(backend)
        .bind(public_id)
        .fetch_optional(&self.pool)
        .await?;
        ory_id.ok_or(DbError::MappingNotFound)
    }

    pub async fn update_tenant(
        &self,
        backend: &str,
        public_id: &str,
        new_tenant_id: &str,
    ) -> Result<(), DbError> {
        let result = sqlx::query(
            "UPDATE id_mappings SET tenant_id = $3 \
             WHERE backend = $1 AND public_id = $2",
        )
        .bind(backend)
        .bind(public_id)
        .bind(new_tenant_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::MappingNotFound);
        }
        Ok(())
    }
}

#[async_trait]
impl IdMappingStore for PgIdMappingStore {
    async fn create(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
        ory_global_id: &str,
    ) -> Result<IdMappingRow, DbError> {
        self.create(tenant_id, backend, public_id, ory_global_id)
            .await
    }

    async fn get_ory_id(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
    ) -> Result<String, DbError> {
        self.get_ory_id(tenant_id, backend, public_id).await
    }

    async fn get_ory_id_by_public_id(
        &self,
        backend: &str,
        public_id: &str,
    ) -> Result<String, DbError> {
        self.get_ory_id_by_public_id(backend, public_id).await
    }

    async fn get_public_id(
        &self,
        tenant_id: &str,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError> {
        self.get_public_id(tenant_id, backend, ory_global_id).await
    }

    async fn get_public_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError> {
        self.get_public_id_by_ory_id(backend, ory_global_id).await
    }

    async fn delete(&self, tenant_id: &str, backend: &str, public_id: &str) -> Result<(), DbError> {
        self.delete(tenant_id, backend, public_id).await
    }

    async fn list_public_ids(
        &self,
        tenant_id: &str,
        backend: &str,
    ) -> Result<Vec<String>, DbError> {
        self.list_public_ids(tenant_id, backend).await
    }

    async fn list_mappings(
        &self,
        tenant_id: &str,
        backend: &str,
    ) -> Result<Vec<IdMappingRow>, DbError> {
        self.list_mappings(tenant_id, backend).await
    }

    async fn get_tenant_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<Option<String>, DbError> {
        self.get_tenant_id_by_ory_id(backend, ory_global_id).await
    }

    async fn update_tenant(
        &self,
        backend: &str,
        public_id: &str,
        new_tenant_id: &str,
    ) -> Result<(), DbError> {
        self.update_tenant(backend, public_id, new_tenant_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for IdMappingRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            backend: row.try_get("backend")?,
            public_id: row.try_get("public_id")?,
            ory_global_id: row.try_get("ory_global_id")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

/// Key of an in-memory mapping row: `(tenant_id, backend, public_id)`.
type MappingKey = (String, String, String);

/// In-memory id-mapping store for tests. `create_at` lets tests control
/// `created_at` (the DCR garbage collector reads registration ages).
#[derive(Clone, Default)]
pub struct MemoryIdMappingStore {
    rows: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<MappingKey, IdMappingRow>>>,
}

impl MemoryIdMappingStore {
    /// Insert a mapping with an explicit `created_at`.
    pub async fn create_at(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
        ory_global_id: &str,
        created_at: time::OffsetDateTime,
    ) -> Result<IdMappingRow, DbError> {
        let mut lock = match self.rows.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let key = (
            tenant_id.to_string(),
            backend.to_string(),
            public_id.to_string(),
        );
        if lock.contains_key(&key) {
            return Err(DbError::MappingNotFound);
        }
        let row = IdMappingRow {
            id: Ulid::new().to_string(),
            tenant_id: tenant_id.to_string(),
            backend: backend.to_string(),
            public_id: public_id.to_string(),
            ory_global_id: ory_global_id.to_string(),
            created_at,
        };
        lock.insert(key, row.clone());
        Ok(row)
    }
}

#[async_trait]
impl IdMappingStore for MemoryIdMappingStore {
    async fn create(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
        ory_global_id: &str,
    ) -> Result<IdMappingRow, DbError> {
        self.create_at(
            tenant_id,
            backend,
            public_id,
            ory_global_id,
            time::OffsetDateTime::now_utc(),
        )
        .await
    }

    async fn get_ory_id(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
    ) -> Result<String, DbError> {
        let lock = match self.rows.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        lock.get(&(
            tenant_id.to_string(),
            backend.to_string(),
            public_id.to_string(),
        ))
        .map(|row| row.ory_global_id.clone())
        .ok_or(DbError::MappingNotFound)
    }

    async fn get_ory_id_by_public_id(
        &self,
        backend: &str,
        public_id: &str,
    ) -> Result<String, DbError> {
        let lock = match self.rows.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        lock.values()
            .find(|row| row.backend == backend && row.public_id == public_id)
            .map(|row| row.ory_global_id.clone())
            .ok_or(DbError::MappingNotFound)
    }

    async fn get_public_id(
        &self,
        tenant_id: &str,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError> {
        let lock = match self.rows.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        lock.values()
            .find(|row| {
                row.tenant_id == tenant_id
                    && row.backend == backend
                    && row.ory_global_id == ory_global_id
            })
            .map(|row| row.public_id.clone())
            .ok_or(DbError::MappingNotFound)
    }

    async fn get_public_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError> {
        let lock = match self.rows.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        lock.values()
            .find(|row| row.backend == backend && row.ory_global_id == ory_global_id)
            .map(|row| row.public_id.clone())
            .ok_or(DbError::MappingNotFound)
    }

    async fn delete(&self, tenant_id: &str, backend: &str, public_id: &str) -> Result<(), DbError> {
        let mut lock = match self.rows.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        lock.remove(&(
            tenant_id.to_string(),
            backend.to_string(),
            public_id.to_string(),
        ))
        .map(|_| ())
        .ok_or(DbError::MappingNotFound)
    }

    async fn list_public_ids(
        &self,
        tenant_id: &str,
        backend: &str,
    ) -> Result<Vec<String>, DbError> {
        Ok(self
            .list_mappings(tenant_id, backend)
            .await?
            .into_iter()
            .map(|row| row.public_id)
            .collect())
    }

    async fn list_mappings(
        &self,
        tenant_id: &str,
        backend: &str,
    ) -> Result<Vec<IdMappingRow>, DbError> {
        let lock = match self.rows.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut rows: Vec<IdMappingRow> = lock
            .values()
            .filter(|row| row.tenant_id == tenant_id && row.backend == backend)
            .cloned()
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.created_at));
        Ok(rows)
    }

    async fn get_tenant_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<Option<String>, DbError> {
        let lock = match self.rows.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        Ok(lock
            .values()
            .find(|row| row.backend == backend && row.ory_global_id == ory_global_id)
            .map(|row| row.tenant_id.clone()))
    }

    async fn update_tenant(
        &self,
        backend: &str,
        public_id: &str,
        new_tenant_id: &str,
    ) -> Result<(), DbError> {
        let mut lock = match self.rows.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let old_key = lock
            .values()
            .find(|row| row.backend == backend && row.public_id == public_id)
            .map(|row| {
                (
                    row.tenant_id.clone(),
                    row.backend.clone(),
                    row.public_id.clone(),
                )
            })
            .ok_or(DbError::MappingNotFound)?;
        if let Some(mut row) = lock.remove(&old_key) {
            row.tenant_id = new_tenant_id.to_string();
            lock.insert(
                (
                    new_tenant_id.to_string(),
                    backend.to_string(),
                    public_id.to_string(),
                ),
                row,
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    #[test]
    fn id_mapping_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = IdMappingRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            backend: "hydra".to_string(),
            public_id: "public".to_string(),
            ory_global_id: "ory".to_string(),
            created_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.backend, "hydra");
    }

    async fn store() -> Arc<dyn IdMappingStore> {
        Arc::new(PgIdMappingStore::new(postgres_pool().await))
    }

    #[tokio::test]
    async fn mapping_lifecycle() {
        let pool = postgres_pool().await;
        let store: Arc<dyn IdMappingStore> = Arc::new(PgIdMappingStore::new(pool.clone()));
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let public_id = format!("public-{}", Ulid::new());
        let ory_id = format!("ory-{}", Ulid::new());

        let row = store
            .create(&tenant, "kratos", &public_id, &ory_id)
            .await
            .unwrap();
        assert_eq!(row.tenant_id, tenant);
        assert_eq!(row.public_id, public_id);
        assert_eq!(row.ory_global_id, ory_id);

        let found_ory = store
            .get_ory_id(&tenant, "kratos", &public_id)
            .await
            .unwrap();
        assert_eq!(found_ory, ory_id);

        let found_public = store
            .get_public_id(&tenant, "kratos", &ory_id)
            .await
            .unwrap();
        assert_eq!(found_public, public_id);

        let tenant_id = store
            .get_tenant_id_by_ory_id("kratos", &ory_id)
            .await
            .unwrap();
        assert_eq!(tenant_id, Some(tenant.clone()));

        let ids = store.list_public_ids(&tenant, "kratos").await.unwrap();
        assert_eq!(ids, vec![public_id.clone()]);

        store.delete(&tenant, "kratos", &public_id).await.unwrap();
        assert!(
            store
                .get_ory_id(&tenant, "kratos", &public_id)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn get_ory_id_returns_not_found_for_missing() {
        let store = store().await;
        let tenant = format!("tenant-{}", Ulid::new());
        let err = store
            .get_ory_id(&tenant, "kratos", "missing")
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::MappingNotFound));
    }

    #[tokio::test]
    async fn get_public_id_returns_not_found_for_missing() {
        let store = store().await;
        let tenant = format!("tenant-{}", Ulid::new());
        let err = store
            .get_public_id(&tenant, "kratos", "missing")
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::MappingNotFound));
    }

    #[tokio::test]
    async fn delete_missing_returns_not_found() {
        let store = store().await;
        let tenant = format!("tenant-{}", Ulid::new());
        let err = store
            .delete(&tenant, "kratos", "missing")
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::MappingNotFound));
    }

    #[tokio::test]
    async fn get_tenant_id_by_ory_id_returns_none_for_missing() {
        let store = store().await;
        let tenant_id = store
            .get_tenant_id_by_ory_id("kratos", "missing")
            .await
            .unwrap();
        assert_eq!(tenant_id, None);
    }

    #[tokio::test]
    async fn list_public_ids_is_empty_for_unknown_tenant() {
        let store = store().await;
        let tenant = format!("tenant-{}", Ulid::new());
        let ids = store.list_public_ids(&tenant, "kratos").await.unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn list_mappings_returns_full_rows() {
        let pool = postgres_pool().await;
        let store: Arc<dyn IdMappingStore> = Arc::new(PgIdMappingStore::new(pool.clone()));
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let public_id = format!("public-{}", Ulid::new());
        store
            .create(&tenant, "hydra", &public_id, "ory-1")
            .await
            .unwrap();

        let rows = store.list_mappings(&tenant, "hydra").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].public_id, public_id);
        assert_eq!(rows[0].ory_global_id, "ory-1");
        assert_eq!(rows[0].tenant_id, tenant);

        // Other backends and tenants are excluded.
        assert!(
            store
                .list_mappings(&tenant, "kratos")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .list_mappings("other-tenant", "hydra")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn pg_update_tenant_rehomes_mapping() {
        let pool = postgres_pool().await;
        let store: Arc<dyn IdMappingStore> = Arc::new(PgIdMappingStore::new(pool.clone()));
        let tenant_a = format!("tenant-{}", Ulid::new());
        let tenant_b = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant_a).await;
        create_test_tenant(&pool, &tenant_b).await;
        let public_id = format!("public-{}", Ulid::new());
        let ory_id = format!("ory-{}", Ulid::new());
        store
            .create(&tenant_a, "hydra", &public_id, &ory_id)
            .await
            .unwrap();

        store
            .update_tenant("hydra", &public_id, &tenant_b)
            .await
            .unwrap();

        // The row now resolves in the new tenant and no longer in the old.
        assert_eq!(
            store
                .get_public_id(&tenant_b, "hydra", &ory_id)
                .await
                .unwrap(),
            public_id
        );
        assert!(matches!(
            store.get_public_id(&tenant_a, "hydra", &ory_id).await,
            Err(DbError::MappingNotFound)
        ));
        assert_eq!(
            store
                .get_tenant_id_by_ory_id("hydra", &ory_id)
                .await
                .unwrap(),
            Some(tenant_b.clone())
        );
        assert_eq!(
            store
                .get_ory_id(&tenant_b, "hydra", &public_id)
                .await
                .unwrap(),
            ory_id
        );
    }

    #[tokio::test]
    async fn pg_update_tenant_missing_mapping_returns_not_found() {
        let store = store().await;
        let err = store
            .update_tenant("hydra", "missing", "tenant")
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::MappingNotFound));
    }

    #[tokio::test]
    async fn memory_update_tenant_rehomes_mapping() {
        let store = MemoryIdMappingStore::default();
        store
            .create("tenant-a", "hydra", "public-1", "ory-1")
            .await
            .unwrap();

        store
            .update_tenant("hydra", "public-1", "tenant-b")
            .await
            .unwrap();

        assert_eq!(
            store
                .get_public_id("tenant-b", "hydra", "ory-1")
                .await
                .unwrap(),
            "public-1"
        );
        assert!(matches!(
            store.get_public_id("tenant-a", "hydra", "ory-1").await,
            Err(DbError::MappingNotFound)
        ));
        assert_eq!(
            store
                .get_tenant_id_by_ory_id("hydra", "ory-1")
                .await
                .unwrap()
                .as_deref(),
            Some("tenant-b")
        );
        assert!(matches!(
            store.update_tenant("hydra", "missing", "tenant-b").await,
            Err(DbError::MappingNotFound)
        ));
    }
}
