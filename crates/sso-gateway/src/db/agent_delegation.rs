use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct AgentDelegationRow {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub user_identity_id: String,
    pub scopes: Vec<String>,
    pub expires_at: time::OffsetDateTime,
    pub revoked_at: Option<time::OffsetDateTime>,
    pub created_at: time::OffsetDateTime,
}

#[async_trait]
pub trait AgentDelegationStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        agent_id: &str,
        user_identity_id: &str,
        scopes: &[String],
        expires_at: time::OffsetDateTime,
    ) -> Result<AgentDelegationRow, DbError>;

    /// Tenant-scoped fetch for the RPC surface.
    async fn get(&self, tenant_id: &str, id: &str) -> Result<AgentDelegationRow, DbError>;

    /// Fetch by id alone; used by the token authority, where the act-token
    /// row already carries the tenant binding.
    async fn get_by_id(&self, id: &str) -> Result<AgentDelegationRow, DbError>;

    /// Mark the grant revoked. Revoking an already-revoked grant is a no-op
    /// that returns the current row.
    async fn revoke(&self, tenant_id: &str, id: &str) -> Result<AgentDelegationRow, DbError>;

    /// Keyset-paginated list of one agent's grants, `(created_at DESC, id DESC)`.
    async fn list_page_by_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<AgentDelegationRow>, i64), DbError>;

    /// Keyset-paginated list of grants made by one user, `(created_at DESC, id DESC)`.
    async fn list_page_by_user(
        &self,
        tenant_id: &str,
        user_identity_id: &str,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<AgentDelegationRow>, i64), DbError>;
}

#[derive(Clone)]
pub struct PgAgentDelegationStore {
    pool: DbPool,
}

const DELEGATION_COLUMNS: &str =
    "id, tenant_id, agent_id, user_identity_id, scopes, expires_at, revoked_at, created_at";

impl PgAgentDelegationStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        agent_id: &str,
        user_identity_id: &str,
        scopes: &[String],
        expires_at: time::OffsetDateTime,
    ) -> Result<AgentDelegationRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, AgentDelegationRow>(&format!(
            "INSERT INTO agent_delegations \
             (id, tenant_id, agent_id, user_identity_id, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING {DELEGATION_COLUMNS}"
        ))
        .bind(&id)
        .bind(tenant_id)
        .bind(agent_id)
        .bind(user_identity_id)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, id: &str) -> Result<AgentDelegationRow, DbError> {
        let row = sqlx::query_as::<_, AgentDelegationRow>(&format!(
            "SELECT {DELEGATION_COLUMNS} FROM agent_delegations \
             WHERE tenant_id = $1 AND id = $2"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::AgentDelegationNotFound)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<AgentDelegationRow, DbError> {
        let row = sqlx::query_as::<_, AgentDelegationRow>(&format!(
            "SELECT {DELEGATION_COLUMNS} FROM agent_delegations WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::AgentDelegationNotFound)
    }

    pub async fn revoke(&self, tenant_id: &str, id: &str) -> Result<AgentDelegationRow, DbError> {
        let row = sqlx::query_as::<_, AgentDelegationRow>(&format!(
            "UPDATE agent_delegations SET revoked_at = COALESCE(revoked_at, NOW()) \
             WHERE tenant_id = $1 AND id = $2 RETURNING {DELEGATION_COLUMNS}"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::AgentDelegationNotFound)
    }

    async fn list_page_by(
        &self,
        tenant_id: &str,
        column: &str,
        value: &str,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<AgentDelegationRow>, i64), DbError> {
        let count_query = format!(
            "SELECT COUNT(*) FROM agent_delegations WHERE tenant_id = $1 AND {column} = $2"
        );
        let total: i64 = sqlx::query_scalar(&count_query)
            .bind(tenant_id)
            .bind(value)
            .fetch_one(&self.pool)
            .await?;

        let mut query = format!(
            "SELECT {DELEGATION_COLUMNS} FROM agent_delegations \
             WHERE tenant_id = $1 AND {column} = $2"
        );
        if after.is_some() {
            query.push_str(" AND (created_at, id) < ($3, $4)");
        }
        query.push_str(if after.is_some() {
            " ORDER BY created_at DESC, id DESC LIMIT $5"
        } else {
            " ORDER BY created_at DESC, id DESC LIMIT $3"
        });

        let mut q = sqlx::query_as::<_, AgentDelegationRow>(&query)
            .bind(tenant_id)
            .bind(value);
        if let Some((created_at, id)) = &after {
            q = q.bind(created_at).bind(id);
        }
        let rows = q.bind(limit as i64).fetch_all(&self.pool).await?;
        Ok((rows, total))
    }

    pub async fn list_page_by_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<AgentDelegationRow>, i64), DbError> {
        self.list_page_by(tenant_id, "agent_id", agent_id, limit, after)
            .await
    }

    pub async fn list_page_by_user(
        &self,
        tenant_id: &str,
        user_identity_id: &str,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<AgentDelegationRow>, i64), DbError> {
        self.list_page_by(
            tenant_id,
            "user_identity_id",
            user_identity_id,
            limit,
            after,
        )
        .await
    }
}

#[async_trait]
impl AgentDelegationStore for PgAgentDelegationStore {
    async fn create(
        &self,
        tenant_id: &str,
        agent_id: &str,
        user_identity_id: &str,
        scopes: &[String],
        expires_at: time::OffsetDateTime,
    ) -> Result<AgentDelegationRow, DbError> {
        self.create(tenant_id, agent_id, user_identity_id, scopes, expires_at)
            .await
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<AgentDelegationRow, DbError> {
        self.get(tenant_id, id).await
    }

    async fn get_by_id(&self, id: &str) -> Result<AgentDelegationRow, DbError> {
        self.get_by_id(id).await
    }

    async fn revoke(&self, tenant_id: &str, id: &str) -> Result<AgentDelegationRow, DbError> {
        self.revoke(tenant_id, id).await
    }

    async fn list_page_by_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<AgentDelegationRow>, i64), DbError> {
        self.list_page_by_agent(tenant_id, agent_id, limit, after)
            .await
    }

    async fn list_page_by_user(
        &self,
        tenant_id: &str,
        user_identity_id: &str,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<AgentDelegationRow>, i64), DbError> {
        self.list_page_by_user(tenant_id, user_identity_id, limit, after)
            .await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for AgentDelegationRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            agent_id: row.try_get("agent_id")?,
            user_identity_id: row.try_get("user_identity_id")?,
            scopes: row.try_get("scopes")?,
            expires_at: row.try_get("expires_at")?,
            revoked_at: row.try_get("revoked_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::db::PgAgentStore;
    use crate::test_support::{create_test_tenant, postgres_pool};

    async fn store_tenant_agent() -> (Arc<dyn AgentDelegationStore>, String, String) {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let agent = PgAgentStore::new(pool.clone())
            .create(&tenant, None, "bot")
            .await
            .unwrap();
        (
            Arc::new(PgAgentDelegationStore::new(pool)),
            tenant,
            agent.id,
        )
    }

    fn expiry() -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc() + time::Duration::hours(1)
    }

    #[test]
    fn delegation_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = AgentDelegationRow {
            id: "d".to_string(),
            tenant_id: "t".to_string(),
            agent_id: "a".to_string(),
            user_identity_id: "u".to_string(),
            scopes: vec!["kanban:read".to_string()],
            expires_at: now,
            revoked_at: None,
            created_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.scopes.len(), 1);
    }

    #[tokio::test]
    async fn delegation_lifecycle() {
        let (store, tenant, agent_id) = store_tenant_agent().await;
        let scopes = vec!["tenant:read".to_string()];

        let created = store
            .create(&tenant, &agent_id, "user-1", &scopes, expiry())
            .await
            .unwrap();
        assert!(created.revoked_at.is_none());
        assert_eq!(created.scopes, scopes);

        let got = store.get(&tenant, &created.id).await.unwrap();
        assert_eq!(got.user_identity_id, "user-1");

        let got_by_id = store.get_by_id(&created.id).await.unwrap();
        assert_eq!(got_by_id.tenant_id, tenant);

        let revoked = store.revoke(&tenant, &created.id).await.unwrap();
        assert!(revoked.revoked_at.is_some());

        // Revoking again is a no-op returning the current row.
        let revoked_again = store.revoke(&tenant, &created.id).await.unwrap();
        assert_eq!(revoked_again.revoked_at, revoked.revoked_at);
    }

    #[tokio::test]
    async fn delegation_not_found_cases() {
        let (store, tenant, _agent_id) = store_tenant_agent().await;
        assert!(matches!(
            store.get(&tenant, "missing").await.unwrap_err(),
            DbError::AgentDelegationNotFound
        ));
        assert!(matches!(
            store.get_by_id("missing").await.unwrap_err(),
            DbError::AgentDelegationNotFound
        ));
        assert!(matches!(
            store.revoke(&tenant, "missing").await.unwrap_err(),
            DbError::AgentDelegationNotFound
        ));
    }

    #[tokio::test]
    async fn delegation_lists_paginate_by_agent_and_user() {
        let (store, tenant, agent_id) = store_tenant_agent().await;
        for _ in 0..3 {
            store
                .create(
                    &tenant,
                    &agent_id,
                    "user-1",
                    &["tenant:read".to_string()],
                    expiry(),
                )
                .await
                .unwrap();
        }
        store
            .create(
                &tenant,
                &agent_id,
                "user-2",
                &["tenant:read".to_string()],
                expiry(),
            )
            .await
            .unwrap();

        let (by_agent, agent_total) = store
            .list_page_by_agent(&tenant, &agent_id, 10, None)
            .await
            .unwrap();
        assert_eq!(agent_total, 4);
        assert_eq!(by_agent.len(), 4);

        let (page1, user_total) = store
            .list_page_by_user(&tenant, "user-1", 2, None)
            .await
            .unwrap();
        assert_eq!(user_total, 3);
        assert_eq!(page1.len(), 2);
        assert!(page1.iter().all(|d| d.user_identity_id == "user-1"));

        let cursor = page1.last().map(|d| (d.created_at, d.id.clone())).unwrap();
        let (page2, _) = store
            .list_page_by_user(&tenant, "user-1", 2, Some(cursor))
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
    }
}
