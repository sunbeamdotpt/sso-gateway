use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

/// Categories of short-lived protocol tokens that are mapped to opaque public
/// tokens before crossing the gateway API boundary.
pub const TOKEN_TYPE_FLOW: &str = "flow";
pub const TOKEN_TYPE_SESSION: &str = "session";
pub const TOKEN_TYPE_LOGOUT_TOKEN: &str = "logout_token";
pub const TOKEN_TYPE_RECOVERY_TOKEN: &str = "recovery_token";
pub const TOKEN_TYPE_VERIFICATION_TOKEN: &str = "verification_token";
pub const TOKEN_TYPE_CONSENT_CHALLENGE: &str = "consent_challenge";
pub const TOKEN_TYPE_LOGIN_CHALLENGE: &str = "login_challenge";
pub const TOKEN_TYPE_LOGOUT_CHALLENGE: &str = "logout_challenge";

#[derive(Debug, Clone)]
pub struct TransientTokenRow {
    pub id: String,
    pub tenant_id: String,
    pub backend: String,
    pub token_type: String,
    pub public_token: String,
    pub ory_token: String,
    pub expires_at: time::OffsetDateTime,
    pub created_at: time::OffsetDateTime,
}

#[async_trait]
pub trait TransientTokenStore: Send + Sync + 'static {
    /// Create a new mapping from a backend token to a freshly generated public
    /// ULID. Returns the public token.
    async fn create(
        &self,
        tenant_id: &str,
        backend: &str,
        token_type: &str,
        ory_token: &str,
        expires_at: time::OffsetDateTime,
    ) -> Result<String, DbError>;

    /// Resolve a public token back to the backend token.
    async fn get_ory_token(
        &self,
        tenant_id: &str,
        backend: &str,
        token_type: &str,
        public_token: &str,
    ) -> Result<String, DbError>;

    /// Find the public token for a backend token, if one already exists.
    async fn get_public_token(
        &self,
        tenant_id: &str,
        backend: &str,
        token_type: &str,
        ory_token: &str,
    ) -> Result<String, DbError>;

    /// Remove a mapping by public token.
    async fn delete(&self, tenant_id: &str, public_token: &str) -> Result<(), DbError>;

    /// Resolve a public token back to the backend token without knowing the
    /// tenant. This is required for unauthenticated protocol endpoints (e.g.
    /// OAuth2 logout challenges) where the caller presents a public token but
    /// no `Authorization` header is available.
    async fn get_ory_token_global(
        &self,
        backend: &str,
        token_type: &str,
        public_token: &str,
    ) -> Result<(String, String), DbError>;
}

#[derive(Clone)]
pub struct PgTransientTokenStore {
    pool: DbPool,
}

impl PgTransientTokenStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        backend: &str,
        token_type: &str,
        ory_token: &str,
        expires_at: time::OffsetDateTime,
    ) -> Result<String, DbError> {
        let id = Ulid::new().to_string();
        let public_token = Ulid::new().to_string();
        sqlx::query(
            "INSERT INTO transient_token_mappings \
             (id, tenant_id, backend, token_type, public_token, ory_token, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (tenant_id, backend, token_type, ory_token) DO UPDATE \
             SET expires_at = EXCLUDED.expires_at \
             RETURNING public_token",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(backend)
        .bind(token_type)
        .bind(&public_token)
        .bind(ory_token)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map(|row| row.get::<String, _>("public_token"))
        .map_err(DbError::from)
    }

    pub async fn get_ory_token(
        &self,
        tenant_id: &str,
        backend: &str,
        token_type: &str,
        public_token: &str,
    ) -> Result<String, DbError> {
        let token: Option<String> = sqlx::query_scalar(
            "SELECT ory_token FROM transient_token_mappings \
             WHERE tenant_id = $1 AND backend = $2 AND token_type = $3 AND public_token = $4 \
             AND expires_at > NOW()",
        )
        .bind(tenant_id)
        .bind(backend)
        .bind(token_type)
        .bind(public_token)
        .fetch_optional(&self.pool)
        .await?;
        token.ok_or(DbError::MappingNotFound)
    }

    pub async fn get_public_token(
        &self,
        tenant_id: &str,
        backend: &str,
        token_type: &str,
        ory_token: &str,
    ) -> Result<String, DbError> {
        let token: Option<String> = sqlx::query_scalar(
            "SELECT public_token FROM transient_token_mappings \
             WHERE tenant_id = $1 AND backend = $2 AND token_type = $3 AND ory_token = $4 \
             AND expires_at > NOW()",
        )
        .bind(tenant_id)
        .bind(backend)
        .bind(token_type)
        .bind(ory_token)
        .fetch_optional(&self.pool)
        .await?;
        token.ok_or(DbError::MappingNotFound)
    }

    pub async fn delete(&self, tenant_id: &str, public_token: &str) -> Result<(), DbError> {
        let result = sqlx::query(
            "DELETE FROM transient_token_mappings \
             WHERE tenant_id = $1 AND public_token = $2",
        )
        .bind(tenant_id)
        .bind(public_token)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::MappingNotFound);
        }
        Ok(())
    }

    pub async fn get_ory_token_global(
        &self,
        backend: &str,
        token_type: &str,
        public_token: &str,
    ) -> Result<(String, String), DbError> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT tenant_id, ory_token FROM transient_token_mappings \
             WHERE backend = $1 AND token_type = $2 AND public_token = $3 \
             AND expires_at > NOW()",
        )
        .bind(backend)
        .bind(token_type)
        .bind(public_token)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::MappingNotFound)
    }
}

#[async_trait]
impl TransientTokenStore for PgTransientTokenStore {
    async fn create(
        &self,
        tenant_id: &str,
        backend: &str,
        token_type: &str,
        ory_token: &str,
        expires_at: time::OffsetDateTime,
    ) -> Result<String, DbError> {
        self.create(tenant_id, backend, token_type, ory_token, expires_at)
            .await
    }

    async fn get_ory_token(
        &self,
        tenant_id: &str,
        backend: &str,
        token_type: &str,
        public_token: &str,
    ) -> Result<String, DbError> {
        self.get_ory_token(tenant_id, backend, token_type, public_token)
            .await
    }

    async fn get_public_token(
        &self,
        tenant_id: &str,
        backend: &str,
        token_type: &str,
        ory_token: &str,
    ) -> Result<String, DbError> {
        self.get_public_token(tenant_id, backend, token_type, ory_token)
            .await
    }

    async fn delete(&self, tenant_id: &str, public_token: &str) -> Result<(), DbError> {
        self.delete(tenant_id, public_token).await
    }

    async fn get_ory_token_global(
        &self,
        backend: &str,
        token_type: &str,
        public_token: &str,
    ) -> Result<(String, String), DbError> {
        self.get_ory_token_global(backend, token_type, public_token)
            .await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TransientTokenRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            backend: row.try_get("backend")?,
            token_type: row.try_get("token_type")?,
            public_token: row.try_get("public_token")?,
            ory_token: row.try_get("ory_token")?,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    async fn store() -> Arc<dyn TransientTokenStore> {
        Arc::new(PgTransientTokenStore::new(postgres_pool().await))
    }

    #[tokio::test]
    async fn mapping_lifecycle() {
        let pool = postgres_pool().await;
        let store: Arc<dyn TransientTokenStore> =
            Arc::new(PgTransientTokenStore::new(pool.clone()));
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let expires = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        let public = store
            .create(&tenant, "kratos", TOKEN_TYPE_FLOW, "ory-flow-1", expires)
            .await
            .unwrap();
        assert!(!public.is_empty());

        let resolved = store
            .get_ory_token(&tenant, "kratos", TOKEN_TYPE_FLOW, &public)
            .await
            .unwrap();
        assert_eq!(resolved, "ory-flow-1");

        let public2 = store
            .get_public_token(&tenant, "kratos", TOKEN_TYPE_FLOW, "ory-flow-1")
            .await
            .unwrap();
        assert_eq!(public2, public);

        store.delete(&tenant, &public).await.unwrap();
        assert!(
            store
                .get_ory_token(&tenant, "kratos", TOKEN_TYPE_FLOW, &public)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn expired_token_returns_not_found() {
        let pool = postgres_pool().await;
        let store: Arc<dyn TransientTokenStore> =
            Arc::new(PgTransientTokenStore::new(pool.clone()));
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let expires = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let public = store
            .create(&tenant, "kratos", TOKEN_TYPE_SESSION, "ory-sess-1", expires)
            .await
            .unwrap();
        let err = store
            .get_ory_token(&tenant, "kratos", TOKEN_TYPE_SESSION, &public)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::MappingNotFound));
    }

    #[tokio::test]
    async fn get_ory_token_returns_not_found_for_missing() {
        let store = store().await;
        let err = store
            .get_ory_token("missing", "kratos", TOKEN_TYPE_FLOW, "missing")
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::MappingNotFound));
    }
}
