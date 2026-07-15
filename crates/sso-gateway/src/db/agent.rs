use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

pub const AGENT_STATUS_ACTIVE: &str = "active";
pub const AGENT_STATUS_DISABLED: &str = "disabled";

#[derive(Debug, Clone)]
pub struct AgentRow {
    pub id: String,
    pub tenant_id: String,
    pub owner_identity_id: Option<String>,
    pub name: String,
    pub status: String,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait AgentStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        owner_identity_id: Option<&str>,
        name: &str,
    ) -> Result<AgentRow, DbError>;

    async fn get(&self, tenant_id: &str, id: &str) -> Result<AgentRow, DbError>;

    /// Fetch an agent's lifecycle status by id alone.
    ///
    /// The middleware resolves the tenant through id_mappings and only needs
    /// the status for the big-red-button check, so no tenant scoping here.
    async fn get_status(&self, id: &str) -> Result<String, DbError>;

    async fn set_name(&self, tenant_id: &str, id: &str, name: &str) -> Result<AgentRow, DbError>;

    async fn set_status(
        &self,
        tenant_id: &str,
        id: &str,
        status: &str,
    ) -> Result<AgentRow, DbError>;

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError>;

    /// Keyset-paginated list ordered by `(created_at DESC, id DESC)`; `after`
    /// is the exclusive keyset cursor of the last row of the previous page.
    async fn list_page(
        &self,
        tenant_id: &str,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<AgentRow>, i64), DbError>;
}

#[derive(Clone)]
pub struct PgAgentStore {
    pool: DbPool,
}

const AGENT_COLUMNS: &str = "id, tenant_id, owner_identity_id, name, status, created_at, updated_at";

impl PgAgentStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        owner_identity_id: Option<&str>,
        name: &str,
    ) -> Result<AgentRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, AgentRow>(
            "INSERT INTO agents (id, tenant_id, owner_identity_id, name) \
             VALUES ($1, $2, $3, $4) \
             RETURNING id, tenant_id, owner_identity_id, name, status, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(owner_identity_id)
        .bind(name)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, id: &str) -> Result<AgentRow, DbError> {
        let row = sqlx::query_as::<_, AgentRow>(&format!(
            "SELECT {AGENT_COLUMNS} FROM agents WHERE tenant_id = $1 AND id = $2"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::AgentNotFound)
    }

    pub async fn get_status(&self, id: &str) -> Result<String, DbError> {
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM agents WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        status.ok_or(DbError::AgentNotFound)
    }

    pub async fn set_name(
        &self,
        tenant_id: &str,
        id: &str,
        name: &str,
    ) -> Result<AgentRow, DbError> {
        let row = sqlx::query_as::<_, AgentRow>(&format!(
            "UPDATE agents SET name = $3, updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2 RETURNING {AGENT_COLUMNS}"
        ))
        .bind(tenant_id)
        .bind(id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::AgentNotFound)
    }

    pub async fn set_status(
        &self,
        tenant_id: &str,
        id: &str,
        status: &str,
    ) -> Result<AgentRow, DbError> {
        let row = sqlx::query_as::<_, AgentRow>(&format!(
            "UPDATE agents SET status = $3, updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2 RETURNING {AGENT_COLUMNS}"
        ))
        .bind(tenant_id)
        .bind(id)
        .bind(status)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::AgentNotFound)
    }

    pub async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
        let result = sqlx::query("DELETE FROM agents WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::AgentNotFound);
        }
        Ok(())
    }

    pub async fn list_page(
        &self,
        tenant_id: &str,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<AgentRow>, i64), DbError> {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?;

        let mut query = format!("SELECT {AGENT_COLUMNS} FROM agents WHERE tenant_id = $1");
        if after.is_some() {
            query.push_str(" AND (created_at, id) < ($2, $3)");
        }
        query.push_str(if after.is_some() {
            " ORDER BY created_at DESC, id DESC LIMIT $4"
        } else {
            " ORDER BY created_at DESC, id DESC LIMIT $2"
        });

        let mut q = sqlx::query_as::<_, AgentRow>(&query).bind(tenant_id);
        if let Some((created_at, id)) = &after {
            q = q.bind(created_at).bind(id);
        }
        let rows = q.bind(limit as i64).fetch_all(&self.pool).await?;
        Ok((rows, total))
    }
}

#[async_trait]
impl AgentStore for PgAgentStore {
    async fn create(
        &self,
        tenant_id: &str,
        owner_identity_id: Option<&str>,
        name: &str,
    ) -> Result<AgentRow, DbError> {
        self.create(tenant_id, owner_identity_id, name).await
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<AgentRow, DbError> {
        self.get(tenant_id, id).await
    }

    async fn get_status(&self, id: &str) -> Result<String, DbError> {
        self.get_status(id).await
    }

    async fn set_name(&self, tenant_id: &str, id: &str, name: &str) -> Result<AgentRow, DbError> {
        self.set_name(tenant_id, id, name).await
    }

    async fn set_status(
        &self,
        tenant_id: &str,
        id: &str,
        status: &str,
    ) -> Result<AgentRow, DbError> {
        self.set_status(tenant_id, id, status).await
    }

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
        self.delete(tenant_id, id).await
    }

    async fn list_page(
        &self,
        tenant_id: &str,
        limit: u32,
        after: Option<(time::OffsetDateTime, String)>,
    ) -> Result<(Vec<AgentRow>, i64), DbError> {
        self.list_page(tenant_id, limit, after).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for AgentRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            owner_identity_id: row.try_get("owner_identity_id")?,
            name: row.try_get("name")?,
            status: row.try_get("status")?,
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

    #[test]
    fn agent_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = AgentRow {
            id: "a".to_string(),
            tenant_id: "t".to_string(),
            owner_identity_id: Some("owner".to_string()),
            name: "bot".to_string(),
            status: AGENT_STATUS_ACTIVE.to_string(),
            created_at: now,
            updated_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.name, "bot");
    }

    async fn store_and_tenant() -> (Arc<dyn AgentStore>, String) {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        (Arc::new(PgAgentStore::new(pool)), tenant)
    }

    #[tokio::test]
    async fn agent_lifecycle() {
        let (store, tenant) = store_and_tenant().await;

        let created = store
            .create(&tenant, Some("user-1"), "kanban-bot")
            .await
            .unwrap();
        assert_eq!(created.status, AGENT_STATUS_ACTIVE);
        assert_eq!(created.owner_identity_id.as_deref(), Some("user-1"));

        let got = store.get(&tenant, &created.id).await.unwrap();
        assert_eq!(got.name, "kanban-bot");

        let status = store.get_status(&created.id).await.unwrap();
        assert_eq!(status, AGENT_STATUS_ACTIVE);

        let renamed = store.set_name(&tenant, &created.id, "renamed").await.unwrap();
        assert_eq!(renamed.name, "renamed");

        let disabled = store
            .set_status(&tenant, &created.id, AGENT_STATUS_DISABLED)
            .await
            .unwrap();
        assert_eq!(disabled.status, AGENT_STATUS_DISABLED);

        store.delete(&tenant, &created.id).await.unwrap();
        assert!(matches!(
            store.get(&tenant, &created.id).await.unwrap_err(),
            DbError::AgentNotFound
        ));
    }

    #[tokio::test]
    async fn agent_not_found_cases() {
        let (store, tenant) = store_and_tenant().await;
        assert!(matches!(
            store.get(&tenant, "missing").await.unwrap_err(),
            DbError::AgentNotFound
        ));
        assert!(matches!(
            store.get_status("missing").await.unwrap_err(),
            DbError::AgentNotFound
        ));
        assert!(matches!(
            store.set_name(&tenant, "missing", "x").await.unwrap_err(),
            DbError::AgentNotFound
        ));
        assert!(matches!(
            store
                .set_status(&tenant, "missing", AGENT_STATUS_DISABLED)
                .await
                .unwrap_err(),
            DbError::AgentNotFound
        ));
        assert!(matches!(
            store.delete(&tenant, "missing").await.unwrap_err(),
            DbError::AgentNotFound
        ));
    }

    #[tokio::test]
    async fn agent_list_page_keyset_paginates() {
        let (store, tenant) = store_and_tenant().await;
        for i in 0..3 {
            store
                .create(&tenant, None, &format!("bot-{i}"))
                .await
                .unwrap();
        }

        let (page1, total) = store.list_page(&tenant, 2, None).await.unwrap();
        assert_eq!(total, 3);
        assert_eq!(page1.len(), 2);

        let cursor = page1
            .last()
            .map(|r| (r.created_at, r.id.clone()))
            .unwrap();
        let (page2, _) = store.list_page(&tenant, 2, Some(cursor)).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert_ne!(page1[0].id, page2[0].id);
    }
}
