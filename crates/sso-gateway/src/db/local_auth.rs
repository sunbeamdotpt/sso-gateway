use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAuthMethod {
    Password,
    Code,
}

impl LocalAuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Code => "code",
        }
    }
}

impl std::str::FromStr for LocalAuthMethod {
    type Err = DbError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "password" => Ok(Self::Password),
            "code" => Ok(Self::Code),
            _ => Err(DbError::InvalidLocalAuthMethod(s.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TenantLocalAuthRow {
    pub id: String,
    pub tenant_id: String,
    pub method: LocalAuthMethod,
    pub config: serde_json::Value,
    pub is_enabled: bool,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait TenantLocalAuthStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        method: LocalAuthMethod,
        config: serde_json::Value,
    ) -> Result<TenantLocalAuthRow, DbError>;

    async fn get_by_tenant_and_method(
        &self,
        tenant_id: &str,
        method: LocalAuthMethod,
    ) -> Result<TenantLocalAuthRow, DbError>;

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TenantLocalAuthRow>, DbError>;

    async fn update_config(
        &self,
        tenant_id: &str,
        id: &str,
        config: serde_json::Value,
    ) -> Result<TenantLocalAuthRow, DbError>;

    async fn set_enabled(
        &self,
        tenant_id: &str,
        id: &str,
        is_enabled: bool,
    ) -> Result<TenantLocalAuthRow, DbError>;
}

#[derive(Clone)]
pub struct PgTenantLocalAuthStore {
    pool: DbPool,
}

impl PgTenantLocalAuthStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        method: LocalAuthMethod,
        config: serde_json::Value,
    ) -> Result<TenantLocalAuthRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, TenantLocalAuthRow>(
            "INSERT INTO tenant_local_auth \
             (id, tenant_id, method, config) \
             VALUES ($1, $2, $3, $4) \
             RETURNING id, tenant_id, method, config, is_enabled, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(method.as_str())
        .bind(sqlx::types::Json(config))
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_by_tenant_and_method(
        &self,
        tenant_id: &str,
        method: LocalAuthMethod,
    ) -> Result<TenantLocalAuthRow, DbError> {
        let row = sqlx::query_as::<_, TenantLocalAuthRow>(
            "SELECT id, tenant_id, method, config, is_enabled, created_at, updated_at \
             FROM tenant_local_auth \
             WHERE tenant_id = $1 AND method = $2 AND is_enabled = TRUE",
        )
        .bind(tenant_id)
        .bind(method.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::LocalAuthNotFound)
    }

    pub async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TenantLocalAuthRow>, DbError> {
        let rows = sqlx::query_as::<_, TenantLocalAuthRow>(
            "SELECT id, tenant_id, method, config, is_enabled, created_at, updated_at \
             FROM tenant_local_auth \
             WHERE tenant_id = $1 \
             ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn update_config(
        &self,
        tenant_id: &str,
        id: &str,
        config: serde_json::Value,
    ) -> Result<TenantLocalAuthRow, DbError> {
        let row = sqlx::query_as::<_, TenantLocalAuthRow>(
            "UPDATE tenant_local_auth \
             SET config = $1, updated_at = NOW() \
             WHERE tenant_id = $2 AND id = $3 \
             RETURNING id, tenant_id, method, config, is_enabled, created_at, updated_at",
        )
        .bind(sqlx::types::Json(config))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::LocalAuthNotFound)
    }

    pub async fn set_enabled(
        &self,
        tenant_id: &str,
        id: &str,
        is_enabled: bool,
    ) -> Result<TenantLocalAuthRow, DbError> {
        let row = sqlx::query_as::<_, TenantLocalAuthRow>(
            "UPDATE tenant_local_auth \
             SET is_enabled = $1, updated_at = NOW() \
             WHERE tenant_id = $2 AND id = $3 \
             RETURNING id, tenant_id, method, config, is_enabled, created_at, updated_at",
        )
        .bind(is_enabled)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::LocalAuthNotFound)
    }
}

#[async_trait]
impl TenantLocalAuthStore for PgTenantLocalAuthStore {
    async fn create(
        &self,
        tenant_id: &str,
        method: LocalAuthMethod,
        config: serde_json::Value,
    ) -> Result<TenantLocalAuthRow, DbError> {
        self.create(tenant_id, method, config).await
    }

    async fn get_by_tenant_and_method(
        &self,
        tenant_id: &str,
        method: LocalAuthMethod,
    ) -> Result<TenantLocalAuthRow, DbError> {
        self.get_by_tenant_and_method(tenant_id, method).await
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TenantLocalAuthRow>, DbError> {
        self.list_by_tenant(tenant_id).await
    }

    async fn update_config(
        &self,
        tenant_id: &str,
        id: &str,
        config: serde_json::Value,
    ) -> Result<TenantLocalAuthRow, DbError> {
        self.update_config(tenant_id, id, config).await
    }

    async fn set_enabled(
        &self,
        tenant_id: &str,
        id: &str,
        is_enabled: bool,
    ) -> Result<TenantLocalAuthRow, DbError> {
        self.set_enabled(tenant_id, id, is_enabled).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TenantLocalAuthRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let method: String = row.try_get("method")?;
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            method: method.parse().map_err(|e: DbError| sqlx::Error::Decode(Box::new(e)))?,
            config: row
                .try_get::<sqlx::types::Json<serde_json::Value>, _>("config")?
                .0,
            is_enabled: row.try_get("is_enabled")?,
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

    async fn store() -> PgTenantLocalAuthStore {
        PgTenantLocalAuthStore::new(postgres_pool().await)
    }

    #[test]
    fn local_auth_method_as_str() {
        assert_eq!(LocalAuthMethod::Password.as_str(), "password");
        assert_eq!(LocalAuthMethod::Code.as_str(), "code");
    }

    #[test]
    fn local_auth_method_from_str_valid() {
        assert_eq!("password".parse::<LocalAuthMethod>().unwrap(), LocalAuthMethod::Password);
        assert_eq!("code".parse::<LocalAuthMethod>().unwrap(), LocalAuthMethod::Code);
    }

    #[test]
    fn local_auth_method_from_str_invalid() {
        let err: DbError = "unknown".parse::<LocalAuthMethod>().unwrap_err();
        assert!(matches!(err, DbError::InvalidLocalAuthMethod(s) if s == "unknown"));
    }

    #[test]
    fn tenant_local_auth_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = TenantLocalAuthRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            method: LocalAuthMethod::Password,
            config: serde_json::json!({"k": "v"}),
            is_enabled: true,
            created_at: now,
            updated_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.method, LocalAuthMethod::Password);
    }

    #[tokio::test]
    async fn local_auth_lifecycle() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let created = store
            .create(&tenant, LocalAuthMethod::Password, serde_json::json!({"min_length": 12}))
            .await
            .unwrap();
        assert_eq!(created.method, LocalAuthMethod::Password);
        assert!(created.is_enabled);

        let found = store
            .get_by_tenant_and_method(&tenant, LocalAuthMethod::Password)
            .await
            .unwrap();
        assert_eq!(found.id, created.id);

        let list = store.list_by_tenant(&tenant).await.unwrap();
        assert_eq!(list.len(), 1);

        let updated = store
            .update_config(&tenant, &created.id, serde_json::json!({"min_length": 16}))
            .await
            .unwrap();
        assert_eq!(updated.config, serde_json::json!({"min_length": 16}));

        let disabled = store.set_enabled(&tenant, &created.id, false).await.unwrap();
        assert!(!disabled.is_enabled);

        let err = store
            .get_by_tenant_and_method(&tenant, LocalAuthMethod::Password)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::LocalAuthNotFound));

        let enabled = store.set_enabled(&tenant, &created.id, true).await.unwrap();
        assert!(enabled.is_enabled);
    }

    #[tokio::test]
    async fn local_auth_not_found_cases() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        assert!(matches!(
            store
                .get_by_tenant_and_method(&tenant, LocalAuthMethod::Code)
                .await
                .unwrap_err(),
            DbError::LocalAuthNotFound
        ));
        assert!(matches!(
            store.update_config(&tenant, "missing", serde_json::json!({})).await.unwrap_err(),
            DbError::LocalAuthNotFound
        ));
        assert!(matches!(
            store.set_enabled(&tenant, "missing", false).await.unwrap_err(),
            DbError::LocalAuthNotFound
        ));
        assert!(store.list_by_tenant(&tenant).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn trait_object_methods() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn TenantLocalAuthStore> = Arc::new(PgTenantLocalAuthStore::new(pool));

        let created = store
            .create(&tenant, LocalAuthMethod::Code, serde_json::json!({}))
            .await
            .unwrap();
        assert!(store.get_by_tenant_and_method(&tenant, LocalAuthMethod::Code).await.is_ok());
        assert_eq!(store.list_by_tenant(&tenant).await.unwrap().len(), 1);
        assert!(store
            .update_config(&tenant, &created.id, serde_json::json!({"ttl": 300}))
            .await
            .is_ok());
    }
}
