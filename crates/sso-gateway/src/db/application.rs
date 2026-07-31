use async_trait::async_trait;
use sqlx::Row;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct ApplicationRow {
    pub tenant_id: String,
    pub public_id: String,
    pub cross_tenant: bool,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait ApplicationStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        public_id: &str,
        cross_tenant: bool,
    ) -> Result<ApplicationRow, DbError>;

    async fn get(
        &self,
        tenant_id: &str,
        public_id: &str,
    ) -> Result<ApplicationRow, DbError>;

    async fn get_by_public_id(&self, public_id: &str) -> Result<ApplicationRow, DbError>;

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<ApplicationRow>, DbError>;

    async fn set_cross_tenant(
        &self,
        tenant_id: &str,
        public_id: &str,
        cross_tenant: bool,
    ) -> Result<ApplicationRow, DbError>;

    async fn delete(&self, tenant_id: &str, public_id: &str) -> Result<(), DbError>;
}

#[derive(Clone)]
pub struct PgApplicationStore {
    pool: DbPool,
}

impl PgApplicationStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        public_id: &str,
        cross_tenant: bool,
    ) -> Result<ApplicationRow, DbError> {
        let row = sqlx::query_as::<_, ApplicationRow>(
            "INSERT INTO applications (tenant_id, public_id, cross_tenant) \
             VALUES ($1, $2, $3) \
             RETURNING tenant_id, public_id, cross_tenant, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(public_id)
        .bind(cross_tenant)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get(
        &self,
        tenant_id: &str,
        public_id: &str,
    ) -> Result<ApplicationRow, DbError> {
        let row = sqlx::query_as::<_, ApplicationRow>(
            "SELECT tenant_id, public_id, cross_tenant, created_at, updated_at \
             FROM applications WHERE tenant_id = $1 AND public_id = $2",
        )
        .bind(tenant_id)
        .bind(public_id)
        .fetch_optional(&self.pool)
        .await?;

        row.ok_or(DbError::ApplicationNotFound)
    }

    pub async fn get_by_public_id(&self, public_id: &str) -> Result<ApplicationRow, DbError> {
        let row = sqlx::query_as::<_, ApplicationRow>(
            "SELECT tenant_id, public_id, cross_tenant, created_at, updated_at \
             FROM applications WHERE public_id = $1",
        )
        .bind(public_id)
        .fetch_optional(&self.pool)
        .await?;

        row.ok_or(DbError::ApplicationNotFound)
    }

    pub async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ApplicationRow>, DbError> {
        let rows = sqlx::query_as::<_, ApplicationRow>(
            "SELECT tenant_id, public_id, cross_tenant, created_at, updated_at \
             FROM applications WHERE tenant_id = $1 ORDER BY public_id",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn set_cross_tenant(
        &self,
        tenant_id: &str,
        public_id: &str,
        cross_tenant: bool,
    ) -> Result<ApplicationRow, DbError> {
        let row = sqlx::query_as::<_, ApplicationRow>(
            "UPDATE applications SET cross_tenant = $3, updated_at = NOW() \
             WHERE tenant_id = $1 AND public_id = $2 \
             RETURNING tenant_id, public_id, cross_tenant, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(public_id)
        .bind(cross_tenant)
        .fetch_optional(&self.pool)
        .await?;

        row.ok_or(DbError::ApplicationNotFound)
    }

    pub async fn delete(&self, tenant_id: &str, public_id: &str) -> Result<(), DbError> {
        let result = sqlx::query(
            "DELETE FROM applications WHERE tenant_id = $1 AND public_id = $2",
        )
        .bind(tenant_id)
        .bind(public_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::ApplicationNotFound);
        }

        Ok(())
    }
}

#[async_trait]
impl ApplicationStore for PgApplicationStore {
    async fn create(
        &self,
        tenant_id: &str,
        public_id: &str,
        cross_tenant: bool,
    ) -> Result<ApplicationRow, DbError> {
        self.create(tenant_id, public_id, cross_tenant).await
    }

    async fn get(
        &self,
        tenant_id: &str,
        public_id: &str,
    ) -> Result<ApplicationRow, DbError> {
        self.get(tenant_id, public_id).await
    }

    async fn get_by_public_id(&self, public_id: &str) -> Result<ApplicationRow, DbError> {
        self.get_by_public_id(public_id).await
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<ApplicationRow>, DbError> {
        self.list_by_tenant(tenant_id).await
    }

    async fn set_cross_tenant(
        &self,
        tenant_id: &str,
        public_id: &str,
        cross_tenant: bool,
    ) -> Result<ApplicationRow, DbError> {
        self.set_cross_tenant(tenant_id, public_id, cross_tenant).await
    }

    async fn delete(&self, tenant_id: &str, public_id: &str) -> Result<(), DbError> {
        self.delete(tenant_id, public_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ApplicationRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            tenant_id: row.try_get("tenant_id")?,
            public_id: row.try_get("public_id")?,
            cross_tenant: row.try_get("cross_tenant")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// In-memory application store for tests.
#[derive(Clone, Default)]
pub struct MemoryApplicationStore {
    records: Arc<Mutex<HashMap<String, ApplicationRow>>>,
}

#[async_trait]
impl ApplicationStore for MemoryApplicationStore {
    async fn create(
        &self,
        tenant_id: &str,
        public_id: &str,
        cross_tenant: bool,
    ) -> Result<ApplicationRow, DbError> {
        let mut lock = match self.records.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if lock.contains_key(public_id) {
            return Err(DbError::ApplicationNotFound);
        }
        let now = time::OffsetDateTime::now_utc();
        let row = ApplicationRow {
            tenant_id: tenant_id.to_string(),
            public_id: public_id.to_string(),
            cross_tenant,
            created_at: now,
            updated_at: now,
        };
        lock.insert(public_id.to_string(), row.clone());
        Ok(row)
    }

    async fn get(
        &self,
        tenant_id: &str,
        public_id: &str,
    ) -> Result<ApplicationRow, DbError> {
        let lock = match self.records.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        lock.get(public_id)
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .ok_or(DbError::ApplicationNotFound)
    }

    async fn get_by_public_id(&self, public_id: &str) -> Result<ApplicationRow, DbError> {
        let lock = match self.records.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        lock.get(public_id).cloned().ok_or(DbError::ApplicationNotFound)
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<ApplicationRow>, DbError> {
        let lock = match self.records.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut rows: Vec<_> = lock
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.public_id.cmp(&b.public_id));
        Ok(rows)
    }

    async fn set_cross_tenant(
        &self,
        tenant_id: &str,
        public_id: &str,
        cross_tenant: bool,
    ) -> Result<ApplicationRow, DbError> {
        let mut lock = match self.records.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let row = lock
            .get_mut(public_id)
            .filter(|r| r.tenant_id == tenant_id)
            .ok_or(DbError::ApplicationNotFound)?;
        row.cross_tenant = cross_tenant;
        row.updated_at = time::OffsetDateTime::now_utc();
        Ok(row.clone())
    }

    async fn delete(&self, tenant_id: &str, public_id: &str) -> Result<(), DbError> {
        let mut lock = match self.records.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if lock
            .get(public_id)
            .filter(|r| r.tenant_id == tenant_id)
            .is_none()
        {
            return Err(DbError::ApplicationNotFound);
        }
        lock.remove(public_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::IdMappingStore;
    use crate::test_support::{create_test_tenant, postgres_pool};

    #[test]
    fn application_row_debug_and_clone() {
        let row = ApplicationRow {
            tenant_id: "t1".to_string(),
            public_id: "p1".to_string(),
            cross_tenant: false,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.public_id, "p1");
    }

    #[tokio::test]
    async fn pg_application_store_round_trip() {
        let pool = postgres_pool().await;
        let store = PgApplicationStore::new(pool.clone());
        let mappings: Arc<dyn IdMappingStore> = Arc::new(crate::db::PgIdMappingStore::new(pool.clone()));
        let tenant_id = ulid::Ulid::new().to_string();
        let public_id = ulid::Ulid::new().to_string();
        create_test_tenant(&pool, &tenant_id).await;
        mappings
            .create(&tenant_id, "hydra", &public_id, "ory-123")
            .await
            .expect("mapping should exist");

        let created = store
            .create(&tenant_id, &public_id, true)
            .await
            .expect("create should succeed");
        assert_eq!(created.tenant_id, tenant_id);
        assert!(created.cross_tenant);

        let fetched = store
            .get(&tenant_id, &public_id)
            .await
            .expect("get should succeed");
        assert_eq!(fetched.public_id, public_id);

        let by_public_id = store
            .get_by_public_id(&public_id)
            .await
            .expect("get_by_public_id should succeed");
        assert!(by_public_id.cross_tenant);

        let updated = store
            .set_cross_tenant(&tenant_id, &public_id, false)
            .await
            .expect("set_cross_tenant should succeed");
        assert!(!updated.cross_tenant);

        let listed = store
            .list_by_tenant(&tenant_id)
            .await
            .expect("list should succeed");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].public_id, public_id);

        store
            .delete(&tenant_id, &public_id)
            .await
            .expect("delete should succeed");
        assert!(matches!(
            store.get(&tenant_id, &public_id).await,
            Err(DbError::ApplicationNotFound)
        ));
    }
}
