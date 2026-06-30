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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    async fn store() -> PgSamlProviderStore {
        PgSamlProviderStore::new(postgres_pool().await)
    }

    #[test]
    fn saml_provider_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = SamlProviderRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            name: "provider".to_string(),
            idp_entity_id: "idp".to_string(),
            idp_sso_url: "https://idp/sso".to_string(),
            idp_certificate_pem: Some("cert".to_string()),
            sp_entity_id: "sp".to_string(),
            acs_url: "https://sp/acs".to_string(),
            name_id_format: Some("email".to_string()),
            schema_id: "schema".to_string(),
            authn_requests_signed: true,
            created_at: now,
            updated_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.name, "provider");
    }

    #[tokio::test]
    async fn provider_lifecycle() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let created = store
            .create(
                &tenant,
                "Test Provider",
                "https://idp/entity",
                "https://idp/sso",
                Some("cert-pem"),
                "https://sp/entity",
                "https://sp/acs",
                Some("email"),
                "default",
                true,
            )
            .await
            .unwrap();
        assert_eq!(created.tenant_id, tenant);
        assert_eq!(created.name, "Test Provider");
        assert_eq!(created.idp_certificate_pem, Some("cert-pem".to_string()));
        assert!(created.authn_requests_signed);

        let found = store.get(&tenant, &created.id).await.unwrap();
        assert_eq!(found.id, created.id);

        let by_id = store.get_by_id(&created.id).await.unwrap();
        assert_eq!(by_id.tenant_id, tenant);

        assert!(matches!(
            store.get(&tenant, "missing").await.unwrap_err(),
            DbError::SamlProviderNotFound
        ));
        assert!(matches!(
            store.get_by_id("missing").await.unwrap_err(),
            DbError::SamlProviderNotFound
        ));
    }

    #[tokio::test]
    async fn trait_object_methods() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn SamlProviderStore> = Arc::new(PgSamlProviderStore::new(pool));

        let created = store
            .create(
                &tenant,
                "Trait Provider",
                "https://idp/entity",
                "https://idp/sso",
                None,
                "https://sp/entity",
                "https://sp/acs",
                None,
                "default",
                false,
            )
            .await
            .unwrap();
        assert!(store.get(&tenant, &created.id).await.is_ok());
        assert!(store.get_by_id(&created.id).await.is_ok());
        assert!(created.idp_certificate_pem.is_none());
        assert!(!created.authn_requests_signed);
    }
}
