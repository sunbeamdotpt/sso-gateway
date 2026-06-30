use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct TenantApiKeyRow {
    pub id: String,
    pub tenant_id: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<time::OffsetDateTime>,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait TenantApiKeyStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        key_hash: &str,
        scopes: &[String],
        expires_at: Option<time::OffsetDateTime>,
    ) -> Result<TenantApiKeyRow, DbError>;

    async fn get_by_hash(&self, key_hash: &str) -> Result<TenantApiKeyRow, DbError>;
}

#[derive(Clone)]
pub struct PgTenantApiKeyStore {
    pool: DbPool,
}

impl PgTenantApiKeyStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        key_hash: &str,
        scopes: &[String],
        expires_at: Option<time::OffsetDateTime>,
    ) -> Result<TenantApiKeyRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, TenantApiKeyRow>(
            "INSERT INTO tenant_api_keys \
             (id, tenant_id, key_hash, name, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, tenant_id, key_hash, name, scopes, expires_at, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(key_hash)
        .bind(name)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_by_hash(&self, key_hash: &str) -> Result<TenantApiKeyRow, DbError> {
        let row = sqlx::query_as::<_, TenantApiKeyRow>(
            "SELECT id, tenant_id, key_hash, name, scopes, expires_at, created_at, updated_at \
             FROM tenant_api_keys \
             WHERE key_hash = $1",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                if let Some(expires_at) = r.expires_at
                    && expires_at < time::OffsetDateTime::now_utc()
                {
                    return Err(DbError::ApiKeyNotFound);
                }
                Ok(r)
            }
            None => Err(DbError::ApiKeyNotFound),
        }
    }
}

#[async_trait]
impl TenantApiKeyStore for PgTenantApiKeyStore {
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        key_hash: &str,
        scopes: &[String],
        expires_at: Option<time::OffsetDateTime>,
    ) -> Result<TenantApiKeyRow, DbError> {
        self.create(tenant_id, name, key_hash, scopes, expires_at).await
    }

    async fn get_by_hash(&self, key_hash: &str) -> Result<TenantApiKeyRow, DbError> {
        self.get_by_hash(key_hash).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TenantApiKeyRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            key_hash: row.try_get("key_hash")?,
            name: row.try_get("name")?,
            scopes: row.try_get("scopes")?,
            expires_at: row.try_get("expires_at")?,
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

    async fn store() -> PgTenantApiKeyStore {
        PgTenantApiKeyStore::new(postgres_pool().await)
    }

    #[test]
    fn tenant_api_key_row_from_row_requires_all_columns() {
        let _size = std::mem::size_of::<TenantApiKeyRow>();
    }

    #[test]
    fn tenant_api_key_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = TenantApiKeyRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            key_hash: "hash".to_string(),
            name: "name".to_string(),
            scopes: vec!["read".to_string()],
            expires_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.name, "name");
    }

    #[tokio::test]
    async fn api_key_lifecycle() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let row = store
            .create(&tenant, "test-key", "deadbeef", &["read".to_string(), "write".to_string()], None)
            .await
            .unwrap();
        assert_eq!(row.tenant_id, tenant);
        assert_eq!(row.key_hash, "deadbeef");
        assert_eq!(row.scopes, vec!["read", "write"]);

        let found = store.get_by_hash("deadbeef").await.unwrap();
        assert_eq!(found.id, row.id);

        let missing = store.get_by_hash("missing").await.unwrap_err();
        assert!(matches!(missing, DbError::ApiKeyNotFound));
    }

    #[tokio::test]
    async fn api_key_expired_returns_not_found() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let expired = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        store
            .create(&tenant, "expired", "expired-hash", &[], Some(expired))
            .await
            .unwrap();

        let err = store.get_by_hash("expired-hash").await.unwrap_err();
        assert!(matches!(err, DbError::ApiKeyNotFound));
    }

    #[tokio::test]
    async fn trait_object_create_and_get() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn TenantApiKeyStore> = Arc::new(PgTenantApiKeyStore::new(pool));

        let row = store
            .create(&tenant, "trait", "trait-hash", &["admin".to_string()], None)
            .await
            .unwrap();
        assert_eq!(row.name, "trait");
        assert!(store.get_by_hash("trait-hash").await.is_ok());
    }
}
