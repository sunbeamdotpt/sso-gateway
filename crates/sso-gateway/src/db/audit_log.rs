use async_trait::async_trait;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use super::{DbError, DbPool};

const GENESIS_HASH: &str = "be6ece231f28401aa8b1615c287eb9e31aa41f4d4d0d24e9eded24238ce6d635";

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
        let created_at = time::OffsetDateTime::now_utc();

        let mut tx = self.pool.begin().await?;

        sqlx::query("SELECT audit_log_advisory_lock()")
            .execute(&mut *tx)
            .await?;

        let prev_hash: Option<String> = sqlx::query_scalar(
            "SELECT integrity_hash FROM audit_log ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let prev_hash = prev_hash.unwrap_or_else(|| GENESIS_HASH.to_string());

        let metadata_str = serde_json::to_string(&metadata).unwrap_or_default();
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            id,
            tenant_id.unwrap_or(""),
            actor.unwrap_or(""),
            action,
            resource,
            outcome,
            metadata_str,
            prev_hash,
            created_at
        );
        let integrity_hash = hex::encode(Sha256::digest(canonical));

        sqlx::query(
            "INSERT INTO audit_log \
             (id, tenant_id, actor, action, resource, outcome, metadata, prev_hash, integrity_hash, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(actor)
        .bind(action)
        .bind(resource)
        .bind(outcome)
        .bind(sqlx::types::Json(metadata))
        .bind(&prev_hash)
        .bind(&integrity_hash)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    #[cfg(test)]
    async fn latest_hash(&self) -> Result<Option<String>, DbError> {
        let hash: Option<String> = sqlx::query_scalar(
            "SELECT integrity_hash FROM audit_log ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(hash)
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
    use crate::db::create_pool;
    use crate::test_support::{create_test_tenant, postgres_pool, postgres_url};

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
            .insert(
                None,
                None,
                "login",
                "session",
                "success",
                serde_json::json!({}),
            )
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

    #[tokio::test]
    async fn hash_chain_links_entries() {
        let base = postgres_url().await;
        let db_name = format!("audit_log_{}", Ulid::new().to_string().to_lowercase());
        let url = db_url_with_name(base, &db_name);
        let pool = create_pool(&url, false).await.unwrap();
        let store = PgAuditLogStore::new(pool);

        store
            .insert(
                None,
                Some("actor-1"),
                "a1",
                "r1",
                "success",
                serde_json::json!({"k": 1}),
            )
            .await
            .unwrap();
        let first_hash = store.latest_hash().await.unwrap().unwrap();

        store
            .insert(
                None,
                Some("actor-2"),
                "a2",
                "r2",
                "failure",
                serde_json::json!({"k": 2}),
            )
            .await
            .unwrap();
        let second_hash = store.latest_hash().await.unwrap().unwrap();

        assert_ne!(first_hash, second_hash);

        let prev: String = sqlx::query_scalar("SELECT prev_hash FROM audit_log WHERE action = $1")
            .bind("a2")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(prev, first_hash);
    }

    fn db_url_with_name(base: &str, db_name: &str) -> String {
        if let Some(query_start) = base.rfind('?') {
            let before_query = &base[..query_start];
            let query = &base[query_start..];
            if let Some(db_sep) = before_query.rfind('/') {
                format!("{}{}{}", &before_query[..db_sep + 1], db_name, query)
            } else {
                format!("{}/{}", before_query, db_name)
            }
        } else if let Some(db_sep) = base.rfind('/') {
            format!("{}{}", &base[..db_sep + 1], db_name)
        } else {
            format!("{}/{}", base, db_name)
        }
    }

    #[tokio::test]
    async fn append_only_trigger_blocks_update() {
        let pool = postgres_pool().await;
        let store = PgAuditLogStore::new(pool);
        store
            .insert(
                None,
                None,
                "action",
                "resource",
                "success",
                serde_json::json!({}),
            )
            .await
            .unwrap();

        let result = sqlx::query("UPDATE audit_log SET outcome = 'failure'")
            .execute(&store.pool)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn append_only_trigger_blocks_delete() {
        let pool = postgres_pool().await;
        let store = PgAuditLogStore::new(pool);
        store
            .insert(
                None,
                None,
                "action",
                "resource",
                "success",
                serde_json::json!({}),
            )
            .await
            .unwrap();

        let result = sqlx::query("DELETE FROM audit_log")
            .execute(&store.pool)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn hash_chain_uses_genesis_for_first_row() {
        let base = postgres_url().await;
        let db_name = format!("audit_log_{}", Ulid::new().to_string().to_lowercase());
        let url = db_url_with_name(base, &db_name);
        let pool = create_pool(&url, false).await.unwrap();
        let store = PgAuditLogStore::new(pool);

        store
            .insert(
                None,
                Some("actor-1"),
                "a1",
                "r1",
                "success",
                serde_json::json!({"k": 1}),
            )
            .await
            .unwrap();

        let prev: String = sqlx::query_scalar("SELECT prev_hash FROM audit_log LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(prev, GENESIS_HASH);
    }

    #[tokio::test]
    async fn truncate_audit_log_is_rejected() {
        let pool = postgres_pool().await;
        let store = PgAuditLogStore::new(pool);
        store
            .insert(
                None,
                None,
                "action",
                "resource",
                "success",
                serde_json::json!({}),
            )
            .await
            .unwrap();

        let result = sqlx::query("TRUNCATE audit_log").execute(&store.pool).await;
        assert!(result.is_err());
    }
}
