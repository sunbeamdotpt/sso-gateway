use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct TenantDomainRow {
    pub id: String,
    pub tenant_id: String,
    pub domain: String,
    pub verification_token: String,
    pub is_verified: bool,
    pub verified_at: Option<time::OffsetDateTime>,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait TenantDomainStore: Send + Sync + 'static {
    async fn create(&self, tenant_id: &str, domain: &str) -> Result<TenantDomainRow, DbError>;

    async fn get_by_domain(&self, domain: &str) -> Result<TenantDomainRow, DbError>;

    async fn mark_verified(&self, tenant_id: &str, id: &str) -> Result<TenantDomainRow, DbError>;

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<TenantDomainRow>, DbError>;
}

#[derive(Clone)]
pub struct PgTenantDomainStore {
    pool: DbPool,
}

impl PgTenantDomainStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, tenant_id: &str, domain: &str) -> Result<TenantDomainRow, DbError> {
        let id = Ulid::new().to_string();
        let verification_token = crate::domain_verification::generate_verification_token();
        let row = sqlx::query_as::<_, TenantDomainRow>(
            "INSERT INTO tenant_domains \
             (id, tenant_id, domain, verification_token) \
             VALUES ($1, $2, $3, $4) \
             RETURNING id, tenant_id, domain, verification_token, is_verified, verified_at, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(domain)
        .bind(&verification_token)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_by_domain(&self, domain: &str) -> Result<TenantDomainRow, DbError> {
        let row = sqlx::query_as::<_, TenantDomainRow>(
            "SELECT id, tenant_id, domain, verification_token, is_verified, verified_at, created_at, updated_at \
             FROM tenant_domains \
             WHERE domain = $1",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::DomainNotFound)
    }

    pub async fn mark_verified(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<TenantDomainRow, DbError> {
        let row = sqlx::query_as::<_, TenantDomainRow>(
            "UPDATE tenant_domains \
             SET is_verified = TRUE, verified_at = NOW(), updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2 \
             RETURNING id, tenant_id, domain, verification_token, is_verified, verified_at, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::DomainNotFound)
    }

    pub async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<TenantDomainRow>, DbError> {
        let rows = sqlx::query_as::<_, TenantDomainRow>(
            "SELECT id, tenant_id, domain, verification_token, is_verified, verified_at, created_at, updated_at \
             FROM tenant_domains \
             WHERE tenant_id = $1 \
             ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[async_trait]
impl TenantDomainStore for PgTenantDomainStore {
    async fn create(&self, tenant_id: &str, domain: &str) -> Result<TenantDomainRow, DbError> {
        self.create(tenant_id, domain).await
    }

    async fn get_by_domain(&self, domain: &str) -> Result<TenantDomainRow, DbError> {
        self.get_by_domain(domain).await
    }

    async fn mark_verified(&self, tenant_id: &str, id: &str) -> Result<TenantDomainRow, DbError> {
        self.mark_verified(tenant_id, id).await
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<TenantDomainRow>, DbError> {
        self.list_by_tenant(tenant_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TenantDomainRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            domain: row.try_get("domain")?,
            verification_token: row.try_get("verification_token")?,
            is_verified: row.try_get("is_verified")?,
            verified_at: row.try_get("verified_at")?,
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

    async fn store() -> PgTenantDomainStore {
        PgTenantDomainStore::new(postgres_pool().await)
    }

    #[test]
    fn tenant_domain_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = TenantDomainRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            domain: "example.com".to_string(),
            verification_token: "token".to_string(),
            is_verified: true,
            verified_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.domain, "example.com");
    }

    #[tokio::test]
    async fn domain_lifecycle() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let domain = format!("domain-{}.example.com", Ulid::new());
        let created = store.create(&tenant, &domain).await.unwrap();
        assert_eq!(created.domain, domain);
        assert!(!created.is_verified);
        assert!(!created.verification_token.is_empty());

        let found = store.get_by_domain(&domain).await.unwrap();
        assert_eq!(found.id, created.id);

        let verified = store.mark_verified(&tenant, &created.id).await.unwrap();
        assert!(verified.is_verified);
        assert!(verified.verified_at.is_some());

        let list = store.list_by_tenant(&tenant).await.unwrap();
        assert_eq!(list.len(), 1);
        assert!(list[0].is_verified);
    }

    #[tokio::test]
    async fn domain_not_found_cases() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        assert!(matches!(
            store
                .get_by_domain("missing.example.com")
                .await
                .unwrap_err(),
            DbError::DomainNotFound
        ));
        assert!(matches!(
            store.mark_verified(&tenant, "missing").await.unwrap_err(),
            DbError::DomainNotFound
        ));
        assert!(store.list_by_tenant(&tenant).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn trait_object_methods() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn TenantDomainStore> = Arc::new(PgTenantDomainStore::new(pool));

        let domain = format!("trait-{}.example.com", Ulid::new());
        let created = store.create(&tenant, &domain).await.unwrap();
        assert!(store.get_by_domain(&domain).await.is_ok());
        assert!(store.mark_verified(&tenant, &created.id).await.is_ok());
        assert_eq!(store.list_by_tenant(&tenant).await.unwrap().len(), 1);
    }
}
