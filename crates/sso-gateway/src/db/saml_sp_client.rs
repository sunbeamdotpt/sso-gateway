use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct SamlSpClientRow {
    pub id: String,
    pub tenant_id: String,
    pub entity_id: String,
    pub acs_url: String,
    pub certificate_pem: Option<String>,
    pub authn_requests_signed: bool,
    pub name_id_format: Option<String>,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait SamlSpClientStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        entity_id: &str,
        acs_url: &str,
        certificate_pem: Option<&str>,
        authn_requests_signed: bool,
        name_id_format: Option<&str>,
    ) -> Result<SamlSpClientRow, DbError>;

    async fn get(&self, tenant_id: &str, id: &str) -> Result<SamlSpClientRow, DbError>;

    async fn get_by_id(&self, id: &str) -> Result<SamlSpClientRow, DbError>;

    async fn get_by_entity_id(
        &self,
        tenant_id: &str,
        entity_id: &str,
    ) -> Result<SamlSpClientRow, DbError>;
}

#[derive(Clone)]
pub struct PgSamlSpClientStore {
    pool: DbPool,
}

impl PgSamlSpClientStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        entity_id: &str,
        acs_url: &str,
        certificate_pem: Option<&str>,
        authn_requests_signed: bool,
        name_id_format: Option<&str>,
    ) -> Result<SamlSpClientRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, SamlSpClientRow>(
            "INSERT INTO saml_sp_clients \
             (id, tenant_id, entity_id, acs_url, certificate_pem, authn_requests_signed, name_id_format) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id, tenant_id, entity_id, acs_url, certificate_pem, authn_requests_signed, name_id_format, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(entity_id)
        .bind(acs_url)
        .bind(certificate_pem)
        .bind(authn_requests_signed)
        .bind(name_id_format)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, id: &str) -> Result<SamlSpClientRow, DbError> {
        let row = sqlx::query_as::<_, SamlSpClientRow>(
            "SELECT id, tenant_id, entity_id, acs_url, certificate_pem, authn_requests_signed, name_id_format, created_at, updated_at \
             FROM saml_sp_clients \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlSpClientNotFound)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<SamlSpClientRow, DbError> {
        let row = sqlx::query_as::<_, SamlSpClientRow>(
            "SELECT id, tenant_id, entity_id, acs_url, certificate_pem, authn_requests_signed, name_id_format, created_at, updated_at \
             FROM saml_sp_clients \
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlSpClientNotFound)
    }

    pub async fn get_by_entity_id(
        &self,
        tenant_id: &str,
        entity_id: &str,
    ) -> Result<SamlSpClientRow, DbError> {
        let row = sqlx::query_as::<_, SamlSpClientRow>(
            "SELECT id, tenant_id, entity_id, acs_url, certificate_pem, authn_requests_signed, name_id_format, created_at, updated_at \
             FROM saml_sp_clients \
             WHERE tenant_id = $1 AND entity_id = $2",
        )
        .bind(tenant_id)
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlSpClientNotFound)
    }
}

#[async_trait]
impl SamlSpClientStore for PgSamlSpClientStore {
    async fn create(
        &self,
        tenant_id: &str,
        entity_id: &str,
        acs_url: &str,
        certificate_pem: Option<&str>,
        authn_requests_signed: bool,
        name_id_format: Option<&str>,
    ) -> Result<SamlSpClientRow, DbError> {
        self.create(
            tenant_id,
            entity_id,
            acs_url,
            certificate_pem,
            authn_requests_signed,
            name_id_format,
        )
        .await
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<SamlSpClientRow, DbError> {
        self.get(tenant_id, id).await
    }

    async fn get_by_id(&self, id: &str) -> Result<SamlSpClientRow, DbError> {
        self.get_by_id(id).await
    }

    async fn get_by_entity_id(
        &self,
        tenant_id: &str,
        entity_id: &str,
    ) -> Result<SamlSpClientRow, DbError> {
        self.get_by_entity_id(tenant_id, entity_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlSpClientRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            entity_id: row.try_get("entity_id")?,
            acs_url: row.try_get("acs_url")?,
            certificate_pem: row.try_get("certificate_pem")?,
            authn_requests_signed: row.try_get("authn_requests_signed")?,
            name_id_format: row.try_get("name_id_format")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}
