use async_trait::async_trait;
use sqlx::Row;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct TenantMembershipRow {
    pub tenant_id: String,
    pub identity_id: String,
    pub schema_id: String,
    pub schema_version: i64,
    pub traits: serde_json::Value,
    pub state: String,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait TenantMembershipStore: Send + Sync + 'static {
    async fn upsert(
        &self,
        tenant_id: &str,
        identity_id: &str,
        schema_id: &str,
        schema_version: i64,
        traits: serde_json::Value,
    ) -> Result<TenantMembershipRow, DbError>;

    async fn get(&self, tenant_id: &str, identity_id: &str)
    -> Result<TenantMembershipRow, DbError>;

    async fn set_state(
        &self,
        tenant_id: &str,
        identity_id: &str,
        state: &str,
    ) -> Result<TenantMembershipRow, DbError>;

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<TenantMembershipRow>, DbError>;
}

#[derive(Clone)]
pub struct PgTenantMembershipStore {
    pool: DbPool,
}

impl PgTenantMembershipStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn upsert(
        &self,
        tenant_id: &str,
        identity_id: &str,
        schema_id: &str,
        schema_version: i64,
        traits: serde_json::Value,
    ) -> Result<TenantMembershipRow, DbError> {
        // `state` is intentionally omitted from the INSERT so the column default
        // ('active') applies on first write, and omitted from the UPDATE so a trait
        // refresh never reactivates a disabled membership.
        let row = sqlx::query_as::<_, TenantMembershipRow>(
            "INSERT INTO tenant_memberships \
             (tenant_id, identity_id, schema_id, schema_version, traits) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (tenant_id, identity_id) DO UPDATE SET \
                 schema_id = EXCLUDED.schema_id, \
                 schema_version = EXCLUDED.schema_version, \
                 traits = EXCLUDED.traits, \
                 updated_at = NOW() \
             RETURNING tenant_id, identity_id, schema_id, schema_version, traits, state, \
                       created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(identity_id)
        .bind(schema_id)
        .bind(schema_version)
        .bind(sqlx::types::Json(traits))
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(
        &self,
        tenant_id: &str,
        identity_id: &str,
    ) -> Result<TenantMembershipRow, DbError> {
        let row = sqlx::query_as::<_, TenantMembershipRow>(
            "SELECT tenant_id, identity_id, schema_id, schema_version, traits, state, \
                    created_at, updated_at \
             FROM tenant_memberships \
             WHERE tenant_id = $1 AND identity_id = $2",
        )
        .bind(tenant_id)
        .bind(identity_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::MembershipNotFound)
    }

    pub async fn set_state(
        &self,
        tenant_id: &str,
        identity_id: &str,
        state: &str,
    ) -> Result<TenantMembershipRow, DbError> {
        let row = sqlx::query_as::<_, TenantMembershipRow>(
            "UPDATE tenant_memberships \
             SET state = $3, updated_at = NOW() \
             WHERE tenant_id = $1 AND identity_id = $2 \
             RETURNING tenant_id, identity_id, schema_id, schema_version, traits, state, \
                       created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(identity_id)
        .bind(state)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::MembershipNotFound)
    }

    pub async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TenantMembershipRow>, DbError> {
        let rows = sqlx::query_as::<_, TenantMembershipRow>(
            "SELECT tenant_id, identity_id, schema_id, schema_version, traits, state, \
                    created_at, updated_at \
             FROM tenant_memberships \
             WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[async_trait]
impl TenantMembershipStore for PgTenantMembershipStore {
    async fn upsert(
        &self,
        tenant_id: &str,
        identity_id: &str,
        schema_id: &str,
        schema_version: i64,
        traits: serde_json::Value,
    ) -> Result<TenantMembershipRow, DbError> {
        self.upsert(tenant_id, identity_id, schema_id, schema_version, traits)
            .await
    }

    async fn get(
        &self,
        tenant_id: &str,
        identity_id: &str,
    ) -> Result<TenantMembershipRow, DbError> {
        self.get(tenant_id, identity_id).await
    }

    async fn set_state(
        &self,
        tenant_id: &str,
        identity_id: &str,
        state: &str,
    ) -> Result<TenantMembershipRow, DbError> {
        self.set_state(tenant_id, identity_id, state).await
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<TenantMembershipRow>, DbError> {
        self.list_by_tenant(tenant_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TenantMembershipRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            tenant_id: row.try_get("tenant_id")?,
            identity_id: row.try_get("identity_id")?,
            schema_id: row.try_get("schema_id")?,
            schema_version: row.try_get("schema_version")?,
            traits: row
                .try_get::<sqlx::types::Json<serde_json::Value>, _>("traits")?
                .0,
            state: row.try_get("state")?,
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
    use ulid::Ulid;

    async fn store() -> PgTenantMembershipStore {
        PgTenantMembershipStore::new(postgres_pool().await)
    }

    fn traits() -> serde_json::Value {
        serde_json::json!({"email": "person@example.com", "name": {"first": "Ada", "last": "Lovelace"}})
    }

    #[test]
    fn membership_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = TenantMembershipRow {
            tenant_id: "t".to_string(),
            identity_id: "i".to_string(),
            schema_id: "employee".to_string(),
            schema_version: 3,
            traits: serde_json::json!({"email": "a@b.c"}),
            state: "active".to_string(),
            created_at: now,
            updated_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.schema_version, 3);
    }

    #[tokio::test]
    async fn membership_upsert_inserts_and_updates() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let identity = format!("id-{}", Ulid::new());

        let created = store
            .upsert(&tenant, &identity, "employee", 1, traits())
            .await
            .unwrap();
        assert_eq!(created.schema_id, "employee");
        assert_eq!(created.schema_version, 1);
        assert_eq!(created.state, "active");
        assert_eq!(created.traits["email"], "person@example.com");

        let updated_traits =
            serde_json::json!({"email": "person@example.com", "name": {"first": "Grace"}});
        let updated = store
            .upsert(&tenant, &identity, "employee", 2, updated_traits.clone())
            .await
            .unwrap();
        assert_eq!(updated.schema_version, 2);
        assert_eq!(updated.traits, updated_traits);
        // State is preserved across trait refreshes.
        assert_eq!(updated.state, "active");
    }

    #[tokio::test]
    async fn membership_set_state_and_get() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let identity = format!("id-{}", Ulid::new());

        store
            .upsert(&tenant, &identity, "employee", 1, traits())
            .await
            .unwrap();
        let disabled = store
            .set_state(&tenant, &identity, "disabled")
            .await
            .unwrap();
        assert_eq!(disabled.state, "disabled");

        // A subsequent upsert must not reactivate a disabled membership.
        store
            .upsert(&tenant, &identity, "employee", 1, traits())
            .await
            .unwrap();
        let got = store.get(&tenant, &identity).await.unwrap();
        assert_eq!(got.state, "disabled");
    }

    #[tokio::test]
    async fn membership_not_found_cases() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        assert!(matches!(
            store.get(&tenant, "missing").await.unwrap_err(),
            DbError::MembershipNotFound
        ));
        assert!(matches!(
            store
                .set_state(&tenant, "missing", "disabled")
                .await
                .unwrap_err(),
            DbError::MembershipNotFound
        ));
        assert!(store.list_by_tenant(&tenant).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn membership_list_and_trait_object() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn TenantMembershipStore> = Arc::new(PgTenantMembershipStore::new(pool));

        let a = format!("id-{}", Ulid::new());
        let b = format!("id-{}", Ulid::new());
        store
            .upsert(&tenant, &a, "employee", 1, traits())
            .await
            .unwrap();
        store
            .upsert(&tenant, &b, "employee", 1, traits())
            .await
            .unwrap();
        assert_eq!(store.list_by_tenant(&tenant).await.unwrap().len(), 2);
        assert!(store.get(&tenant, &a).await.is_ok());
    }
}
