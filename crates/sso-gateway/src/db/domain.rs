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
    async fn create(
        &self,
        tenant_id: &str,
        domain: &str,
    ) -> Result<TenantDomainRow, DbError>;

    async fn get_by_domain(&self, domain: &str) -> Result<TenantDomainRow, DbError>;

    async fn mark_verified(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<TenantDomainRow, DbError>;

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TenantDomainRow>, DbError>;
}

#[derive(Clone)]
pub struct PgTenantDomainStore {
    pool: DbPool,
}

impl PgTenantDomainStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        domain: &str,
    ) -> Result<TenantDomainRow, DbError> {
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

    pub async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TenantDomainRow>, DbError> {
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
    async fn create(
        &self,
        tenant_id: &str,
        domain: &str,
    ) -> Result<TenantDomainRow, DbError> {
        self.create(tenant_id, domain).await
    }

    async fn get_by_domain(&self, domain: &str) -> Result<TenantDomainRow, DbError> {
        self.get_by_domain(domain).await
    }

    async fn mark_verified(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<TenantDomainRow, DbError> {
        self.mark_verified(tenant_id, id).await
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TenantDomainRow>, DbError> {
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
