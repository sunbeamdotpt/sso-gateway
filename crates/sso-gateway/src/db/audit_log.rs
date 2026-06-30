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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    #[tokio::test]
    async fn insert_audit_log_with_tenant() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store = PgAuditLogStore::new(pool);

        store
            .insert(
                Some(&tenant),
                Some("actor-1"),
                "create",
                "tenant",
                "success",
                serde_json::json!({"meta": "data"}),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn insert_audit_log_without_tenant_or_actor() {
        let store = PgAuditLogStore::new(postgres_pool().await);
        store
            .insert(None, None, "login", "session", "success", serde_json::json!({}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn trait_object_insert() {
        let store: Arc<dyn AuditLogStore> = Arc::new(PgAuditLogStore::new(postgres_pool().await));
        store
            .insert(
                None,
                Some("actor"),
                "action",
                "resource",
                "success",
                serde_json::json!({}),
            )
            .await
            .unwrap();
    }
}
