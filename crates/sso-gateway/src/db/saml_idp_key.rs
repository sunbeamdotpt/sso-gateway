use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct SamlIdpKeyRow {
    pub id: String,
    pub tenant_id: String,
    pub key_id: String,
    pub private_key_pem: String,
    pub certificate_pem: String,
    pub is_active: bool,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait SamlIdpKeyStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        key_id: &str,
        private_key_pem: &str,
        certificate_pem: &str,
        is_active: bool,
    ) -> Result<SamlIdpKeyRow, DbError>;

    async fn get_active(&self, tenant_id: &str) -> Result<SamlIdpKeyRow, DbError>;

    async fn list(&self, tenant_id: &str) -> Result<Vec<SamlIdpKeyRow>, DbError>;
}

#[derive(Clone)]
pub struct PgSamlIdpKeyStore {
    pool: DbPool,
}

impl PgSamlIdpKeyStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        key_id: &str,
        private_key_pem: &str,
        certificate_pem: &str,
        is_active: bool,
    ) -> Result<SamlIdpKeyRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, SamlIdpKeyRow>(
            "INSERT INTO saml_idp_keys \
             (id, tenant_id, key_id, private_key_pem, certificate_pem, is_active) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, tenant_id, key_id, private_key_pem, certificate_pem, is_active, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(key_id)
        .bind(private_key_pem)
        .bind(certificate_pem)
        .bind(is_active)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_active(&self, tenant_id: &str) -> Result<SamlIdpKeyRow, DbError> {
        let row = sqlx::query_as::<_, SamlIdpKeyRow>(
            "SELECT id, tenant_id, key_id, private_key_pem, certificate_pem, is_active, created_at, updated_at \
             FROM saml_idp_keys \
             WHERE tenant_id = $1 AND is_active = true \
             ORDER BY created_at DESC \
             LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlIdpKeyNotFound)
    }

    pub async fn list(&self, tenant_id: &str) -> Result<Vec<SamlIdpKeyRow>, DbError> {
        let rows = sqlx::query_as::<_, SamlIdpKeyRow>(
            "SELECT id, tenant_id, key_id, private_key_pem, certificate_pem, is_active, created_at, updated_at \
             FROM saml_idp_keys \
             WHERE tenant_id = $1 \
             ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[async_trait]
impl SamlIdpKeyStore for PgSamlIdpKeyStore {
    async fn create(
        &self,
        tenant_id: &str,
        key_id: &str,
        private_key_pem: &str,
        certificate_pem: &str,
        is_active: bool,
    ) -> Result<SamlIdpKeyRow, DbError> {
        self.create(
            tenant_id,
            key_id,
            private_key_pem,
            certificate_pem,
            is_active,
        )
        .await
    }

    async fn get_active(&self, tenant_id: &str) -> Result<SamlIdpKeyRow, DbError> {
        self.get_active(tenant_id).await
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<SamlIdpKeyRow>, DbError> {
        self.list(tenant_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlIdpKeyRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            key_id: row.try_get("key_id")?,
            private_key_pem: row.try_get("private_key_pem")?,
            certificate_pem: row.try_get("certificate_pem")?,
            is_active: row.try_get("is_active")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}
