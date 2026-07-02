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

    /// Look up a pending SAML request by its id alone. Required by the public
    /// HTTP ACS endpoint, which does not receive the tenant id in the POST body.
    async fn get_by_request_id(&self, request_id: &str) -> Result<SamlRequestRow, DbError>;

    async fn delete(&self, tenant_id: &str, request_id: &str) -> Result<(), DbError>;

    /// Store an inbound SAML AuthnRequest ID seen by the SAML IdP endpoint.
    /// Duplicate IDs are rejected with `DbError::SamlRequestReplay`.
    async fn create_inbound(
        &self,
        tenant_id: &str,
        provider_id: &str,
        request_id: &str,
        ttl: std::time::Duration,
    ) -> Result<(), DbError>;
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

    pub async fn get_by_request_id(&self, request_id: &str) -> Result<SamlRequestRow, DbError> {
        let row = sqlx::query_as::<_, SamlRequestRow>(
            "SELECT id, tenant_id, provider_id, relay_state, created_at \
             FROM saml_requests \
             WHERE id = $1",
        )
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

    pub async fn create_inbound(
        &self,
        tenant_id: &str,
        provider_id: &str,
        request_id: &str,
        ttl: std::time::Duration,
    ) -> Result<(), DbError> {
        let expires_at = time::OffsetDateTime::now_utc() + ttl;
        let result = sqlx::query(
            "INSERT INTO saml_inbound_requests \
             (id, tenant_id, provider_id, expires_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(request_id)
        .bind(tenant_id)
        .bind(provider_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::SamlRequestReplay);
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
        self.create(tenant_id, request_id, provider_id, relay_state)
            .await
    }

    async fn get(&self, tenant_id: &str, request_id: &str) -> Result<SamlRequestRow, DbError> {
        self.get(tenant_id, request_id).await
    }

    async fn get_by_request_id(&self, request_id: &str) -> Result<SamlRequestRow, DbError> {
        self.get_by_request_id(request_id).await
    }

    async fn delete(&self, tenant_id: &str, request_id: &str) -> Result<(), DbError> {
        self.delete(tenant_id, request_id).await
    }

    async fn create_inbound(
        &self,
        tenant_id: &str,
        provider_id: &str,
        request_id: &str,
        ttl: std::time::Duration,
    ) -> Result<(), DbError> {
        self.create_inbound(tenant_id, provider_id, request_id, ttl)
            .await
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};
    use ulid::Ulid;

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

    async fn store() -> PgSamlRequestStore {
        PgSamlRequestStore::new(postgres_pool().await)
    }

    #[test]
    fn saml_request_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = SamlRequestRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            provider_id: "provider".to_string(),
            relay_state: "state".to_string(),
            created_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.relay_state, "state");
    }

    #[tokio::test]
    async fn request_lifecycle() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let provider = create_provider(&pool, &tenant).await;

        let request_id = format!("req-{}", Ulid::new());
        let created = store
            .create(&tenant, &request_id, &provider, "relay-state-1")
            .await
            .unwrap();
        assert_eq!(created.id, request_id);
        assert_eq!(created.tenant_id, tenant);
        assert_eq!(created.provider_id, provider);

        let found = store.get(&tenant, &request_id).await.unwrap();
        assert_eq!(found.relay_state, "relay-state-1");

        store.delete(&tenant, &request_id).await.unwrap();
        assert!(matches!(
            store.get(&tenant, &request_id).await.unwrap_err(),
            DbError::SamlRequestNotFound
        ));
    }

    #[tokio::test]
    async fn request_not_found_cases() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        assert!(matches!(
            store.get(&tenant, "missing").await.unwrap_err(),
            DbError::SamlRequestNotFound
        ));
        assert!(matches!(
            store.delete(&tenant, "missing").await.unwrap_err(),
            DbError::SamlRequestNotFound
        ));
    }

    #[tokio::test]
    async fn trait_object_methods() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let provider = create_provider(&pool, &tenant).await;
        let store: Arc<dyn SamlRequestStore> = Arc::new(PgSamlRequestStore::new(pool));

        let request_id = format!("trait-req-{}", Ulid::new());
        store
            .create(&tenant, &request_id, &provider, "state")
            .await
            .unwrap();
        assert!(store.get(&tenant, &request_id).await.is_ok());
        assert!(store.delete(&tenant, &request_id).await.is_ok());
    }

    #[tokio::test]
    async fn inbound_request_rejects_replays() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let provider_id = "sp-1";
        let request_id = format!("inbound-req-{}", Ulid::new());

        store
            .create_inbound(
                &tenant,
                provider_id,
                &request_id,
                std::time::Duration::from_secs(300),
            )
            .await
            .unwrap();

        let err = store
            .create_inbound(
                &tenant,
                provider_id,
                &request_id,
                std::time::Duration::from_secs(300),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::SamlRequestReplay));
    }
}
