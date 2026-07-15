use async_trait::async_trait;
use sqlx::Row;

use super::{DbError, DbPool};

/// A minted on-behalf-of access token. Only the SHA-256 hash of the bearer
/// token is persisted; the raw token is returned to the agent once at mint.
#[derive(Debug, Clone)]
pub struct AgentActTokenRow {
    pub token_hash: String,
    pub delegation_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub user_identity_id: String,
    pub scopes: Vec<String>,
    pub expires_at: time::OffsetDateTime,
    pub created_at: time::OffsetDateTime,
}

#[async_trait]
pub trait AgentActTokenStore: Send + Sync + 'static {
    #[allow(clippy::too_many_arguments)]
    async fn insert(
        &self,
        token_hash: &str,
        delegation_id: &str,
        tenant_id: &str,
        agent_id: &str,
        user_identity_id: &str,
        scopes: &[String],
        expires_at: time::OffsetDateTime,
    ) -> Result<(), DbError>;

    /// Look up a minted act-token by its SHA-256 hash.
    ///
    /// Returns `Ok(None)` when the hash is unknown, which is the normal path
    /// for bearer tokens that are not act-tokens (Hydra-minted tokens).
    async fn get_by_hash(&self, token_hash: &str) -> Result<Option<AgentActTokenRow>, DbError>;
}

#[derive(Clone)]
pub struct PgAgentActTokenStore {
    pool: DbPool,
}

impl PgAgentActTokenStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert(
        &self,
        token_hash: &str,
        delegation_id: &str,
        tenant_id: &str,
        agent_id: &str,
        user_identity_id: &str,
        scopes: &[String],
        expires_at: time::OffsetDateTime,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO agent_act_tokens \
             (token_hash, delegation_id, tenant_id, agent_id, user_identity_id, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(token_hash)
        .bind(delegation_id)
        .bind(tenant_id)
        .bind(agent_id)
        .bind(user_identity_id)
        .bind(scopes)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_by_hash(&self, token_hash: &str) -> Result<Option<AgentActTokenRow>, DbError> {
        let row = sqlx::query_as::<_, AgentActTokenRow>(
            "SELECT token_hash, delegation_id, tenant_id, agent_id, user_identity_id, scopes, \
                    expires_at, created_at \
             FROM agent_act_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }
}

#[async_trait]
impl AgentActTokenStore for PgAgentActTokenStore {
    async fn insert(
        &self,
        token_hash: &str,
        delegation_id: &str,
        tenant_id: &str,
        agent_id: &str,
        user_identity_id: &str,
        scopes: &[String],
        expires_at: time::OffsetDateTime,
    ) -> Result<(), DbError> {
        self.insert(
            token_hash,
            delegation_id,
            tenant_id,
            agent_id,
            user_identity_id,
            scopes,
            expires_at,
        )
        .await
    }

    async fn get_by_hash(&self, token_hash: &str) -> Result<Option<AgentActTokenRow>, DbError> {
        self.get_by_hash(token_hash).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for AgentActTokenRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            token_hash: row.try_get("token_hash")?,
            delegation_id: row.try_get("delegation_id")?,
            tenant_id: row.try_get("tenant_id")?,
            agent_id: row.try_get("agent_id")?,
            user_identity_id: row.try_get("user_identity_id")?,
            scopes: row.try_get("scopes")?,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::db::{PgAgentDelegationStore, PgAgentStore};
    use crate::test_support::{create_test_tenant, postgres_pool};
    use ulid::Ulid;

    #[test]
    fn act_token_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = AgentActTokenRow {
            token_hash: "h".to_string(),
            delegation_id: "d".to_string(),
            tenant_id: "t".to_string(),
            agent_id: "a".to_string(),
            user_identity_id: "u".to_string(),
            scopes: vec![],
            expires_at: now,
            created_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.token_hash, "h");
    }

    #[tokio::test]
    async fn act_token_insert_and_lookup() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let agent = PgAgentStore::new(pool.clone())
            .create(&tenant, None, "bot")
            .await
            .unwrap();
        let delegation = PgAgentDelegationStore::new(pool.clone())
            .create(
                &tenant,
                &agent.id,
                "user-1",
                &["tenant:read".to_string()],
                time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            )
            .await
            .unwrap();

        let store: Arc<dyn AgentActTokenStore> = Arc::new(PgAgentActTokenStore::new(pool));
        let expires_at = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        store
            .insert(
                "hash-1",
                &delegation.id,
                &tenant,
                &agent.id,
                "user-1",
                &["tenant:read".to_string()],
                expires_at,
            )
            .await
            .unwrap();

        let found = store.get_by_hash("hash-1").await.unwrap().unwrap();
        assert_eq!(found.delegation_id, delegation.id);
        assert_eq!(found.scopes, vec!["tenant:read".to_string()]);

        // Unknown hashes are a normal miss, not an error.
        assert!(store.get_by_hash("hash-unknown").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn act_tokens_cascade_with_delegation() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let agent = PgAgentStore::new(pool.clone())
            .create(&tenant, None, "bot")
            .await
            .unwrap();
        let delegation = PgAgentDelegationStore::new(pool.clone())
            .create(
                &tenant,
                &agent.id,
                "user-1",
                &["tenant:read".to_string()],
                time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            )
            .await
            .unwrap();
        let store = PgAgentActTokenStore::new(pool.clone());
        store
            .insert(
                "hash-cascade",
                &delegation.id,
                &tenant,
                &agent.id,
                "user-1",
                &[],
                time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            )
            .await
            .unwrap();

        // Deleting the agent cascades through delegations to act-tokens.
        PgAgentStore::new(pool.clone())
            .delete(&tenant, &agent.id)
            .await
            .unwrap();
        assert!(store.get_by_hash("hash-cascade").await.unwrap().is_none());
    }
}
