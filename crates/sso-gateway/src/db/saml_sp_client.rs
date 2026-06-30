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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    async fn store() -> PgSamlSpClientStore {
        PgSamlSpClientStore::new(postgres_pool().await)
    }

    #[test]
    fn saml_sp_client_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = SamlSpClientRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            entity_id: "entity".to_string(),
            acs_url: "https://sp/acs".to_string(),
            certificate_pem: Some("cert".to_string()),
            authn_requests_signed: true,
            name_id_format: Some("email".to_string()),
            created_at: now,
            updated_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.entity_id, "entity");
    }

    #[tokio::test]
    async fn sp_client_lifecycle() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let entity_id = format!("https://sp-{}/entity", Ulid::new());
        let created = store
            .create(&tenant, &entity_id, "https://sp/acs", Some("cert-pem"), true, Some("email"))
            .await
            .unwrap();
        assert_eq!(created.entity_id, entity_id);
        assert!(created.authn_requests_signed);

        let found = store.get(&tenant, &created.id).await.unwrap();
        assert_eq!(found.id, created.id);

        let by_id = store.get_by_id(&created.id).await.unwrap();
        assert_eq!(by_id.tenant_id, tenant);

        let by_entity = store.get_by_entity_id(&tenant, &entity_id).await.unwrap();
        assert_eq!(by_entity.id, created.id);

        assert!(matches!(
            store.get(&tenant, "missing").await.unwrap_err(),
            DbError::SamlSpClientNotFound
        ));
        assert!(matches!(
            store.get_by_id("missing").await.unwrap_err(),
            DbError::SamlSpClientNotFound
        ));
        assert!(matches!(
            store.get_by_entity_id(&tenant, "missing").await.unwrap_err(),
            DbError::SamlSpClientNotFound
        ));
    }

    #[tokio::test]
    async fn trait_object_methods() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn SamlSpClientStore> = Arc::new(PgSamlSpClientStore::new(pool));

        let entity_id = format!("https://trait-sp-{}/entity", Ulid::new());
        let created = store
            .create(&tenant, &entity_id, "https://sp/acs", None, false, None)
            .await
            .unwrap();
        assert!(store.get(&tenant, &created.id).await.is_ok());
        assert!(store.get_by_id(&created.id).await.is_ok());
        assert!(store.get_by_entity_id(&tenant, &entity_id).await.is_ok());
        assert!(created.certificate_pem.is_none());
    }
}
