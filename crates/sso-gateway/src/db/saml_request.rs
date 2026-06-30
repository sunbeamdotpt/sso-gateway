use async_trait::async_trait;
use sqlx::Row;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct SamlRequestRow {
    pub id: String,
    pub tenant_id: String,
    pub provider_id: String,
    pub relay_state: String,
    pub created_at: time::OffsetDateTime,
}

#[async_trait]
pub trait SamlRequestStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        request_id: &str,
        provider_id: &str,
        relay_state: &str,
    ) -> Result<SamlRequestRow, DbError>;

    async fn get(&self, tenant_id: &str, request_id: &str) -> Result<SamlRequestRow, DbError>;

    async fn delete(&self, tenant_id: &str, request_id: &str) -> Result<(), DbError>;
}

#[derive(Clone)]
pub struct PgSamlRequestStore {
    pool: DbPool,
}

impl PgSamlRequestStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        request_id: &str,
        provider_id: &str,
        relay_state: &str,
    ) -> Result<SamlRequestRow, DbError> {
        let row = sqlx::query_as::<_, SamlRequestRow>(
            "INSERT INTO saml_requests \
             (id, tenant_id, provider_id, relay_state) \
             VALUES ($1, $2, $3, $4) \
             RETURNING id, tenant_id, provider_id, relay_state, created_at",
        )
        .bind(request_id)
        .bind(tenant_id)
        .bind(provider_id)
        .bind(relay_state)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, request_id: &str) -> Result<SamlRequestRow, DbError> {
        let row = sqlx::query_as::<_, SamlRequestRow>(
            "SELECT id, tenant_id, provider_id, relay_state, created_at \
             FROM saml_requests \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlRequestNotFound)
    }

    pub async fn delete(&self, tenant_id: &str, request_id: &str) -> Result<(), DbError> {
        let result = sqlx::query("DELETE FROM saml_requests WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(request_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::SamlRequestNotFound);
        }
        Ok(())
    }
}

#[async_trait]
impl SamlRequestStore for PgSamlRequestStore {
    async fn create(
        &self,
        tenant_id: &str,
        request_id: &str,
        provider_id: &str,
        relay_state: &str,
    ) -> Result<SamlRequestRow, DbError> {
        self.create(tenant_id, request_id, provider_id, relay_state).await
    }

    async fn get(&self, tenant_id: &str, request_id: &str) -> Result<SamlRequestRow, DbError> {
        self.get(tenant_id, request_id).await
    }

    async fn delete(&self, tenant_id: &str, request_id: &str) -> Result<(), DbError> {
        self.delete(tenant_id, request_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlRequestRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            provider_id: row.try_get("provider_id")?,
            relay_state: row.try_get("relay_state")?,
            created_at: row.try_get("created_at")?,
        })
    }
}
