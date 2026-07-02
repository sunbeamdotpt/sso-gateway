use async_trait::async_trait;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::{DbError, DbPool};

/// Store for server-side gateway session metadata.
///
/// A session is considered active when it has been issued, has not expired, and
/// has not been revoked. The session id itself is never stored in the browser;
/// only a hash of it is kept in the database.
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    /// Record a newly issued session.
    async fn create(
        &self,
        session_id: &str,
        sub: &str,
        tenant_id: &str,
        amr: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), DbError>;

    /// Check whether a session exists, has not expired, and is not revoked.
    async fn is_active(&self, session_id: &str) -> Result<bool, DbError>;

    /// Revoke a single session.
    async fn revoke(&self, session_id: &str) -> Result<(), DbError>;

    /// Revoke all sessions for a subject.
    async fn revoke_all_for_subject(&self, sub: &str) -> Result<(), DbError>;
}

fn hash_session_id(session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Clone)]
pub struct PgSessionStore {
    pool: DbPool,
}

impl PgSessionStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionStore for PgSessionStore {
    async fn create(
        &self,
        session_id: &str,
        sub: &str,
        tenant_id: &str,
        amr: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), DbError> {
        let hash = hash_session_id(session_id);
        sqlx::query(
            "INSERT INTO gateway_sessions \
             (session_hash, sub, tenant_id, amr, expires_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (session_hash) DO NOTHING",
        )
        .bind(&hash)
        .bind(sub)
        .bind(tenant_id)
        .bind(amr)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn is_active(&self, session_id: &str) -> Result<bool, DbError> {
        let hash = hash_session_id(session_id);
        let row: Option<(bool,)> = sqlx::query_as(
            "SELECT TRUE FROM gateway_sessions \
             WHERE session_hash = $1 \
             AND expires_at > NOW() \
             AND revoked_at IS NULL",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    async fn revoke(&self, session_id: &str) -> Result<(), DbError> {
        let hash = hash_session_id(session_id);
        sqlx::query("UPDATE gateway_sessions SET revoked_at = NOW() WHERE session_hash = $1")
            .bind(&hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revoke_all_for_subject(&self, sub: &str) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE gateway_sessions SET revoked_at = NOW() WHERE sub = $1 AND revoked_at IS NULL",
        )
        .bind(sub)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    #[tokio::test]
    async fn session_lifecycle() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", ulid::Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store = PgSessionStore::new(pool);
        let sid = format!("sid-{}", ulid::Ulid::new());

        assert!(!store.is_active(&sid).await.unwrap());
        store
            .create(
                &sid,
                "sub-1",
                &tenant,
                "oidc",
                OffsetDateTime::now_utc() + time::Duration::hours(1),
            )
            .await
            .unwrap();
        assert!(store.is_active(&sid).await.unwrap());

        store.revoke(&sid).await.unwrap();
        assert!(!store.is_active(&sid).await.unwrap());
    }

    #[tokio::test]
    async fn expired_session_is_inactive() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", ulid::Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store = PgSessionStore::new(pool);
        let sid = format!("sid-{}", ulid::Ulid::new());

        store
            .create(
                &sid,
                "sub-1",
                &tenant,
                "oidc",
                OffsetDateTime::now_utc() - time::Duration::seconds(1),
            )
            .await
            .unwrap();
        assert!(!store.is_active(&sid).await.unwrap());
    }

    #[tokio::test]
    async fn revoke_all_for_subject() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", ulid::Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn SessionStore> = Arc::new(PgSessionStore::new(pool));
        let sid1 = format!("sid-{}", ulid::Ulid::new());
        let sid2 = format!("sid-{}", ulid::Ulid::new());

        store
            .create(
                &sid1,
                "sub-1",
                &tenant,
                "oidc",
                OffsetDateTime::now_utc() + time::Duration::hours(1),
            )
            .await
            .unwrap();
        store
            .create(
                &sid2,
                "sub-1",
                &tenant,
                "oidc",
                OffsetDateTime::now_utc() + time::Duration::hours(1),
            )
            .await
            .unwrap();

        store.revoke_all_for_subject("sub-1").await.unwrap();
        assert!(!store.is_active(&sid1).await.unwrap());
        assert!(!store.is_active(&sid2).await.unwrap());
    }
}
