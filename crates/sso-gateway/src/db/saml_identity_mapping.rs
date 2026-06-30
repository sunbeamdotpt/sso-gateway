use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct SamlIdentityMappingRow {
    pub id: String,
    pub tenant_id: String,
    pub provider_id: String,
    pub name_id: String,
    pub identity_public_id: String,
    pub ory_global_id: String,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait SamlIdentityMappingStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        provider_id: &str,
        name_id: &str,
        identity_public_id: &str,
        ory_global_id: &str,
    ) -> Result<SamlIdentityMappingRow, DbError>;

    async fn get_by_name_id(
        &self,
        tenant_id: &str,
        provider_id: &str,
        name_id: &str,
    ) -> Result<SamlIdentityMappingRow, DbError>;
}

#[derive(Clone)]
pub struct PgSamlIdentityMappingStore {
    pool: DbPool,
}

impl PgSamlIdentityMappingStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        provider_id: &str,
        name_id: &str,
        identity_public_id: &str,
        ory_global_id: &str,
    ) -> Result<SamlIdentityMappingRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, SamlIdentityMappingRow>(
            "INSERT INTO saml_identity_mappings \
             (id, tenant_id, provider_id, name_id, identity_public_id, ory_global_id) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, tenant_id, provider_id, name_id, identity_public_id, ory_global_id, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(provider_id)
        .bind(name_id)
        .bind(identity_public_id)
        .bind(ory_global_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_by_name_id(
        &self,
        tenant_id: &str,
        provider_id: &str,
        name_id: &str,
    ) -> Result<SamlIdentityMappingRow, DbError> {
        let row = sqlx::query_as::<_, SamlIdentityMappingRow>(
            "SELECT id, tenant_id, provider_id, name_id, identity_public_id, ory_global_id, created_at, updated_at \
             FROM saml_identity_mappings \
             WHERE tenant_id = $1 AND provider_id = $2 AND name_id = $3",
        )
        .bind(tenant_id)
        .bind(provider_id)
        .bind(name_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlIdentityMappingNotFound)
    }
}

#[async_trait]
impl SamlIdentityMappingStore for PgSamlIdentityMappingStore {
    async fn create(
        &self,
        tenant_id: &str,
        provider_id: &str,
        name_id: &str,
        identity_public_id: &str,
        ory_global_id: &str,
    ) -> Result<SamlIdentityMappingRow, DbError> {
        self.create(
            tenant_id,
            provider_id,
            name_id,
            identity_public_id,
            ory_global_id,
        )
        .await
    }

    async fn get_by_name_id(
        &self,
        tenant_id: &str,
        provider_id: &str,
        name_id: &str,
    ) -> Result<SamlIdentityMappingRow, DbError> {
        self.get_by_name_id(tenant_id, provider_id, name_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlIdentityMappingRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            provider_id: row.try_get("provider_id")?,
            name_id: row.try_get("name_id")?,
            identity_public_id: row.try_get("identity_public_id")?,
            ory_global_id: row.try_get("ory_global_id")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}
