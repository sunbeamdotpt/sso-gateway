use async_trait::async_trait;
use ulid::Ulid;

use super::{DbError, DbPool};

#[async_trait]
pub trait AuditLogStore: Send + Sync + 'static {
    async fn insert(
        &self,
        tenant_id: Option<&str>,
        actor: Option<&str>,
        action: &str,
        resource: &str,
        outcome: &str,
        metadata: serde_json::Value,
    ) -> Result<(), DbError>;
}

#[derive(Clone)]
pub struct PgAuditLogStore {
    pool: DbPool,
}

impl PgAuditLogStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn insert(
        &self,
        tenant_id: Option<&str>,
        actor: Option<&str>,
        action: &str,
        resource: &str,
        outcome: &str,
        metadata: serde_json::Value,
    ) -> Result<(), DbError> {
        let id = Ulid::new().to_string();
        sqlx::query(
            "INSERT INTO audit_log \
             (id, tenant_id, actor, action, resource, outcome, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(actor)
        .bind(action)
        .bind(resource)
        .bind(outcome)
        .bind(sqlx::types::Json(metadata))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl AuditLogStore for PgAuditLogStore {
    async fn insert(
        &self,
        tenant_id: Option<&str>,
        actor: Option<&str>,
        action: &str,
        resource: &str,
        outcome: &str,
        metadata: serde_json::Value,
    ) -> Result<(), DbError> {
        self.insert(tenant_id, actor, action, resource, outcome, metadata)
            .await
    }
}
