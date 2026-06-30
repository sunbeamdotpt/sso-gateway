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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    async fn create_provider(pool: &DbPool, tenant_id: &str) -> String {
        let provider_id = Ulid::new().to_string();
        sqlx::query(
            "INSERT INTO saml_providers \
             (id, tenant_id, name, idp_entity_id, idp_sso_url, sp_entity_id, acs_url, schema_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&provider_id)
        .bind(tenant_id)
        .bind("Test Provider")
        .bind("https://idp/entity")
        .bind("https://idp/sso")
        .bind("https://sp/entity")
        .bind("https://sp/acs")
        .bind("default")
        .execute(pool)
        .await
        .expect("insert provider");
        provider_id
    }

    async fn store() -> PgSamlIdentityMappingStore {
        PgSamlIdentityMappingStore::new(postgres_pool().await)
    }

    #[test]
    fn saml_identity_mapping_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = SamlIdentityMappingRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            provider_id: "provider".to_string(),
            name_id: "name".to_string(),
            identity_public_id: "identity".to_string(),
            ory_global_id: "ory".to_string(),
            created_at: now,
            updated_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.name_id, "name");
    }

    #[tokio::test]
    async fn mapping_lifecycle() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let provider = create_provider(&pool, &tenant).await;

        let created = store
            .create(&tenant, &provider, "nameid-1", "public-1", "ory-1")
            .await
            .unwrap();
        assert_eq!(created.tenant_id, tenant);
        assert_eq!(created.provider_id, provider);
        assert_eq!(created.name_id, "nameid-1");

        let found = store
            .get_by_name_id(&tenant, &provider, "nameid-1")
            .await
            .unwrap();
        assert_eq!(found.id, created.id);

        assert!(matches!(
            store
                .get_by_name_id(&tenant, &provider, "missing")
                .await
                .unwrap_err(),
            DbError::SamlIdentityMappingNotFound
        ));
    }

    #[tokio::test]
    async fn trait_object_methods() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let provider = create_provider(&pool, &tenant).await;
        let store: Arc<dyn SamlIdentityMappingStore> =
            Arc::new(PgSamlIdentityMappingStore::new(pool));

        let created = store
            .create(&tenant, &provider, "nameid-2", "public-2", "ory-2")
            .await
            .unwrap();
        assert!(store.get_by_name_id(&tenant, &provider, "nameid-2").await.is_ok());
        assert_eq!(created.identity_public_id, "public-2");
    }
}
