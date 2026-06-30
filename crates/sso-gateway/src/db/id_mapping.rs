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

    async fn get_public_id(
        &self,
        tenant_id: &str,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError>;

    async fn delete(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
    ) -> Result<(), DbError>;

    async fn list_public_ids(
        &self,
        tenant_id: &str,
        backend: &str,
    ) -> Result<Vec<String>, DbError>;

    /// Find the tenant that owns a given Ory global id for a backend.
    async fn get_tenant_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<Option<String>, DbError>;
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
        self.create(tenant_id, backend, public_id, ory_global_id).await
    }

    async fn get_ory_id(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
    ) -> Result<String, DbError> {
        self.get_ory_id(tenant_id, backend, public_id).await
    }

    async fn get_public_id(
        &self,
        tenant_id: &str,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError> {
        self.get_public_id(tenant_id, backend, ory_global_id).await
    }

    async fn delete(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
    ) -> Result<(), DbError> {
        self.delete(tenant_id, backend, public_id).await
    }

    async fn list_public_ids(
        &self,
        tenant_id: &str,
        backend: &str,
    ) -> Result<Vec<String>, DbError> {
        self.list_public_ids(tenant_id, backend).await
    }

    async fn get_tenant_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<Option<String>, DbError> {
        self.get_tenant_id_by_ory_id(backend, ory_global_id).await
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
