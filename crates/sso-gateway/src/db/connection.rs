use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Oidc,
    OAuth2,
    Saml,
}

impl ConnectionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::OAuth2 => "oauth2",
            Self::Saml => "saml",
        }
    }
}

impl std::str::FromStr for ConnectionType {
    type Err = DbError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "oidc" => Ok(Self::Oidc),
            "oauth2" => Ok(Self::OAuth2),
            "saml" => Ok(Self::Saml),
            _ => Err(DbError::InvalidConnectionType(s.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TenantConnectionRow {
    pub id: String,
    pub tenant_id: String,
    pub connection_type: ConnectionType,
    pub domain: String,
    pub config: serde_json::Value,
    pub is_enabled: bool,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait TenantConnectionStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        connection_type: ConnectionType,
        domain: &str,
        config: serde_json::Value,
    ) -> Result<TenantConnectionRow, DbError>;

    async fn get_by_domain(&self, domain: &str) -> Result<TenantConnectionRow, DbError>;

    async fn get_by_id(&self, tenant_id: &str, id: &str) -> Result<TenantConnectionRow, DbError>;

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TenantConnectionRow>, DbError>;

    async fn update_config(
        &self,
        tenant_id: &str,
        id: &str,
        config: serde_json::Value,
    ) -> Result<TenantConnectionRow, DbError>;

    async fn set_enabled(
        &self,
        tenant_id: &str,
        id: &str,
        is_enabled: bool,
    ) -> Result<TenantConnectionRow, DbError>;
}

#[derive(Clone)]
pub struct PgTenantConnectionStore {
    pool: DbPool,
}

impl PgTenantConnectionStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        connection_type: ConnectionType,
        domain: &str,
        config: serde_json::Value,
    ) -> Result<TenantConnectionRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, TenantConnectionRow>(
            "INSERT INTO tenant_connections \
             (id, tenant_id, connection_type, domain, config) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, tenant_id, connection_type, domain, config, is_enabled, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(connection_type.as_str())
        .bind(domain)
        .bind(sqlx::types::Json(config))
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_by_domain(&self, domain: &str) -> Result<TenantConnectionRow, DbError> {
        let row = sqlx::query_as::<_, TenantConnectionRow>(
            "SELECT id, tenant_id, connection_type, domain, config, is_enabled, created_at, updated_at \
             FROM tenant_connections \
             WHERE domain = $1 AND is_enabled = TRUE",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::ConnectionNotFound)
    }

    pub async fn get_by_id(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<TenantConnectionRow, DbError> {
        let row = sqlx::query_as::<_, TenantConnectionRow>(
            "SELECT id, tenant_id, connection_type, domain, config, is_enabled, created_at, updated_at \
             FROM tenant_connections \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::ConnectionNotFound)
    }

    pub async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TenantConnectionRow>, DbError> {
        let rows = sqlx::query_as::<_, TenantConnectionRow>(
            "SELECT id, tenant_id, connection_type, domain, config, is_enabled, created_at, updated_at \
             FROM tenant_connections \
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
    ) -> Result<TenantConnectionRow, DbError> {
        let row = sqlx::query_as::<_, TenantConnectionRow>(
            "UPDATE tenant_connections \
             SET config = $1, updated_at = NOW() \
             WHERE tenant_id = $2 AND id = $3 \
             RETURNING id, tenant_id, connection_type, domain, config, is_enabled, created_at, updated_at",
        )
        .bind(sqlx::types::Json(config))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::ConnectionNotFound)
    }

    pub async fn set_enabled(
        &self,
        tenant_id: &str,
        id: &str,
        is_enabled: bool,
    ) -> Result<TenantConnectionRow, DbError> {
        let row = sqlx::query_as::<_, TenantConnectionRow>(
            "UPDATE tenant_connections \
             SET is_enabled = $1, updated_at = NOW() \
             WHERE tenant_id = $2 AND id = $3 \
             RETURNING id, tenant_id, connection_type, domain, config, is_enabled, created_at, updated_at",
        )
        .bind(is_enabled)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::ConnectionNotFound)
    }
}

#[async_trait]
impl TenantConnectionStore for PgTenantConnectionStore {
    async fn create(
        &self,
        tenant_id: &str,
        connection_type: ConnectionType,
        domain: &str,
        config: serde_json::Value,
    ) -> Result<TenantConnectionRow, DbError> {
        self.create(tenant_id, connection_type, domain, config).await
    }

    async fn get_by_domain(&self, domain: &str) -> Result<TenantConnectionRow, DbError> {
        self.get_by_domain(domain).await
    }

    async fn get_by_id(&self, tenant_id: &str, id: &str) -> Result<TenantConnectionRow, DbError> {
        self.get_by_id(tenant_id, id).await
    }

    async fn list_by_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TenantConnectionRow>, DbError> {
        self.list_by_tenant(tenant_id).await
    }

    async fn update_config(
        &self,
        tenant_id: &str,
        id: &str,
        config: serde_json::Value,
    ) -> Result<TenantConnectionRow, DbError> {
        self.update_config(tenant_id, id, config).await
    }

    async fn set_enabled(
        &self,
        tenant_id: &str,
        id: &str,
        is_enabled: bool,
    ) -> Result<TenantConnectionRow, DbError> {
        self.set_enabled(tenant_id, id, is_enabled).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TenantConnectionRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let connection_type: String = row.try_get("connection_type")?;
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            connection_type: connection_type
                .parse()
                .map_err(|e: DbError| sqlx::Error::Decode(Box::new(e)))?,
            domain: row.try_get("domain")?,
            config: row
                .try_get::<sqlx::types::Json<serde_json::Value>, _>("config")?
                .0,
            is_enabled: row.try_get("is_enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}
