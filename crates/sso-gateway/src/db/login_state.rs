use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct LoginStateRow {
    pub state_token: String,
    pub tenant_id: String,
    pub connection_id: String,
    pub connection_type: String,
    pub return_to: String,
    pub code_verifier: Option<String>,
    pub nonce: Option<String>,
    pub created_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

#[async_trait]
pub trait LoginStateStore: Send + Sync + 'static {
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        tenant_id: &str,
        connection_id: &str,
        connection_type: &str,
        return_to: &str,
        code_verifier: Option<String>,
        nonce: Option<String>,
        ttl: std::time::Duration,
    ) -> Result<LoginStateRow, DbError>;

    async fn get(&self, state_token: &str) -> Result<LoginStateRow, DbError>;

    async fn delete(&self, state_token: &str) -> Result<(), DbError>;
}

#[derive(Clone)]
pub struct PgLoginStateStore {
    pool: DbPool,
}

impl PgLoginStateStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LoginStateStore for PgLoginStateStore {
    async fn create(
        &self,
        tenant_id: &str,
        connection_id: &str,
        connection_type: &str,
        return_to: &str,
        code_verifier: Option<String>,
        nonce: Option<String>,
        ttl: std::time::Duration,
    ) -> Result<LoginStateRow, DbError> {
        let state_token = Ulid::new().to_string();
        let expires_at = time::OffsetDateTime::now_utc() + ttl;
        let row = sqlx::query_as::<_, LoginStateRow>(
            "INSERT INTO login_state \
             (state_token, tenant_id, connection_id, connection_type, return_to, code_verifier, nonce, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             RETURNING state_token, tenant_id, connection_id, connection_type, return_to, code_verifier, nonce, created_at, expires_at",
        )
        .bind(&state_token)
        .bind(tenant_id)
        .bind(connection_id)
        .bind(connection_type)
        .bind(return_to)
        .bind(code_verifier)
        .bind(nonce)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    async fn get(&self, state_token: &str) -> Result<LoginStateRow, DbError> {
        let row = sqlx::query_as::<_, LoginStateRow>(
            "SELECT state_token, tenant_id, connection_id, connection_type, return_to, code_verifier, nonce, created_at, expires_at \
             FROM login_state \
             WHERE state_token = $1 AND expires_at > NOW()",
        )
        .bind(state_token)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::LoginStateNotFound)
    }

    async fn delete(&self, state_token: &str) -> Result<(), DbError> {
        let result = sqlx::query("DELETE FROM login_state WHERE state_token = $1")
            .bind(state_token)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::LoginStateNotFound);
        }
        Ok(())
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for LoginStateRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            state_token: row.try_get("state_token")?,
            tenant_id: row.try_get("tenant_id")?,
            connection_id: row.try_get("connection_id")?,
            connection_type: row.try_get("connection_type")?,
            return_to: row.try_get("return_to")?,
            code_verifier: row.try_get("code_verifier")?,
            nonce: row.try_get("nonce")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    async fn store() -> PgLoginStateStore {
        PgLoginStateStore::new(postgres_pool().await)
    }

    #[tokio::test]
    async fn login_state_lifecycle() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let created = store
            .create(
                &tenant,
                "conn-1",
                "oidc",
                "https://app.example.com",
                Some("verifier-1".into()),
                Some("nonce-1".into()),
                std::time::Duration::from_secs(300),
            )
            .await
            .unwrap();
        assert_eq!(created.tenant_id, tenant);
        assert_eq!(created.connection_id, "conn-1");
        assert_eq!(created.connection_type, "oidc");
        assert_eq!(created.return_to, "https://app.example.com");
        assert_eq!(created.code_verifier, Some("verifier-1".into()));
        assert_eq!(created.nonce, Some("nonce-1".into()));

        let found = store.get(&created.state_token).await.unwrap();
        assert_eq!(found.state_token, created.state_token);

        store.delete(&created.state_token).await.unwrap();
        assert!(matches!(
            store.get(&created.state_token).await.unwrap_err(),
            DbError::LoginStateNotFound
        ));
    }

    #[tokio::test]
    async fn login_state_not_found_for_missing_token() {
        let store = store().await;
        assert!(matches!(
            store.get("missing").await.unwrap_err(),
            DbError::LoginStateNotFound
        ));
        assert!(matches!(
            store.delete("missing").await.unwrap_err(),
            DbError::LoginStateNotFound
        ));
    }

    #[tokio::test]
    async fn login_state_expired_token_not_returned() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let created = store
            .create(
                &tenant,
                "conn-1",
                "oidc",
                "https://app.example.com",
                None,
                None,
                std::time::Duration::from_secs(0),
            )
            .await
            .unwrap();

        // Wait briefly to ensure expiration.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(matches!(
            store.get(&created.state_token).await.unwrap_err(),
            DbError::LoginStateNotFound
        ));
    }

    #[tokio::test]
    async fn trait_object_methods() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn LoginStateStore> = Arc::new(PgLoginStateStore::new(pool));

        let created = store
            .create(
                &tenant,
                "conn-1",
                "oauth2",
                "https://app.example.com",
                Some("verifier-2".into()),
                None,
                std::time::Duration::from_secs(300),
            )
            .await
            .unwrap();
        assert_eq!(created.code_verifier, Some("verifier-2".into()));
        assert!(store.get(&created.state_token).await.is_ok());
        assert!(store.delete(&created.state_token).await.is_ok());
    }
}
