use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct SamlProviderRow {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub idp_entity_id: String,
    pub idp_sso_url: String,
    pub idp_certificate_pem: Option<String>,
    pub sp_entity_id: String,
    pub acs_url: String,
    pub name_id_format: Option<String>,
    pub schema_id: String,
    pub authn_requests_signed: bool,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait SamlProviderStore: Send + Sync + 'static {
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        idp_entity_id: &str,
        idp_sso_url: &str,
        idp_certificate_pem: Option<&str>,
        sp_entity_id: &str,
        acs_url: &str,
        name_id_format: Option<&str>,
        schema_id: &str,
        authn_requests_signed: bool,
    ) -> Result<SamlProviderRow, DbError>;

    async fn get(&self, tenant_id: &str, id: &str) -> Result<SamlProviderRow, DbError>;

    async fn get_by_id(&self, id: &str) -> Result<SamlProviderRow, DbError>;
}

#[derive(Clone)]
pub struct PgSamlProviderStore {
    pool: DbPool,
}

impl PgSamlProviderStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        idp_entity_id: &str,
        idp_sso_url: &str,
        idp_certificate_pem: Option<&str>,
        sp_entity_id: &str,
        acs_url: &str,
        name_id_format: Option<&str>,
        schema_id: &str,
        authn_requests_signed: bool,
    ) -> Result<SamlProviderRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, SamlProviderRow>(
            "INSERT INTO saml_providers \
             (id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate_pem, sp_entity_id, acs_url, name_id_format, schema_id, authn_requests_signed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             RETURNING id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate_pem, sp_entity_id, acs_url, name_id_format, schema_id, authn_requests_signed, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .bind(idp_entity_id)
        .bind(idp_sso_url)
        .bind(idp_certificate_pem)
        .bind(sp_entity_id)
        .bind(acs_url)
        .bind(name_id_format)
        .bind(schema_id)
        .bind(authn_requests_signed)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, id: &str) -> Result<SamlProviderRow, DbError> {
        let row = sqlx::query_as::<_, SamlProviderRow>(
            "SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate_pem, sp_entity_id, acs_url, name_id_format, schema_id, authn_requests_signed, created_at, updated_at \
             FROM saml_providers \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlProviderNotFound)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<SamlProviderRow, DbError> {
        let row = sqlx::query_as::<_, SamlProviderRow>(
            "SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate_pem, sp_entity_id, acs_url, name_id_format, schema_id, authn_requests_signed, created_at, updated_at \
             FROM saml_providers \
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlProviderNotFound)
    }
}

#[async_trait]
impl SamlProviderStore for PgSamlProviderStore {
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        idp_entity_id: &str,
        idp_sso_url: &str,
        idp_certificate_pem: Option<&str>,
        sp_entity_id: &str,
        acs_url: &str,
        name_id_format: Option<&str>,
        schema_id: &str,
        authn_requests_signed: bool,
    ) -> Result<SamlProviderRow, DbError> {
        self.create(
            tenant_id,
            name,
            idp_entity_id,
            idp_sso_url,
            idp_certificate_pem,
            sp_entity_id,
            acs_url,
            name_id_format,
            schema_id,
            authn_requests_signed,
        )
        .await
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<SamlProviderRow, DbError> {
        self.get(tenant_id, id).await
    }

    async fn get_by_id(&self, id: &str) -> Result<SamlProviderRow, DbError> {
        self.get_by_id(id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlProviderRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            idp_entity_id: row.try_get("idp_entity_id")?,
            idp_sso_url: row.try_get("idp_sso_url")?,
            idp_certificate_pem: row.try_get("idp_certificate_pem")?,
            sp_entity_id: row.try_get("sp_entity_id")?,
            acs_url: row.try_get("acs_url")?,
            name_id_format: row.try_get("name_id_format")?,
            schema_id: row.try_get("schema_id")?,
            authn_requests_signed: row.try_get("authn_requests_signed")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}
