use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct TenantRow {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub is_system: bool,
    pub settings: serde_json::Value,
}

#[async_trait]
pub trait TenantStore: Send + Sync + 'static {
    async fn create(
        &self,
        slug: &str,
        display_name: &str,
        settings: serde_json::Value,
    ) -> Result<TenantRow, DbError>;

    async fn get_by_id(&self, id: &str) -> Result<TenantRow, DbError>;

    async fn list(&self) -> Result<Vec<TenantRow>, DbError>;
}

#[derive(Clone)]
pub struct PgTenantStore {
    pool: DbPool,
}

impl PgTenantStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    pub async fn create(
        &self,
        slug: &str,
        display_name: &str,
        settings: serde_json::Value,
    ) -> Result<TenantRow, DbError> {
        let id = Ulid::new().to_string();

        let row = sqlx::query_as::<_, TenantRow>(
            "INSERT INTO tenants (id, slug, display_name, settings) VALUES ($1, $2, $3, $4) RETURNING id, slug, display_name, is_system, settings",
        )
        .bind(&id)
        .bind(slug)
        .bind(display_name)
        .bind(sqlx::types::Json(settings))
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<TenantRow, DbError> {
        let row = sqlx::query_as::<_, TenantRow>(
            "SELECT id, slug, display_name, is_system, settings FROM tenants WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.ok_or(DbError::TenantNotFound)
    }

    pub async fn list(&self) -> Result<Vec<TenantRow>, DbError> {
        let rows = sqlx::query_as::<_, TenantRow>(
            "SELECT id, slug, display_name, is_system, settings FROM tenants ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }
}

#[async_trait]
impl TenantStore for PgTenantStore {
    async fn create(
        &self,
        slug: &str,
        display_name: &str,
        settings: serde_json::Value,
    ) -> Result<TenantRow, DbError> {
        self.create(slug, display_name, settings).await
    }

    async fn get_by_id(&self, id: &str) -> Result<TenantRow, DbError> {
        self.get_by_id(id).await
    }

    async fn list(&self) -> Result<Vec<TenantRow>, DbError> {
        self.list().await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TenantRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            slug: row.try_get("slug")?,
            display_name: row.try_get("display_name")?,
            is_system: row.try_get("is_system")?,
            settings: row
                .try_get::<sqlx::types::Json<serde_json::Value>, _>("settings")?
                .0,
        })
    }
}
