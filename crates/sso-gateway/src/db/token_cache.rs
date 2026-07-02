use async_trait::async_trait;
use sqlx::Row;

use super::{DbError, DbPool};

/// Cached result of an OAuth2 token introspection call.
#[derive(Debug, Clone)]
pub struct TokenIntrospectionRow {
    pub token_hash: String,
    pub active: bool,
    pub sub: Option<String>,
    pub scope: Option<String>,
    pub exp: Option<time::OffsetDateTime>,
    pub cached_at: time::OffsetDateTime,
}

#[async_trait]
pub trait TokenIntrospectionCache: Send + Sync + 'static {
    /// Look up a cached introspection result.
    ///
    /// Returns `Ok(None)` if there is no usable cached entry (missing, expired,
    /// or older than `max_age`).
    async fn get(
        &self,
        token_hash: &str,
        max_age: time::Duration,
    ) -> Result<Option<TokenIntrospectionRow>, DbError>;

    /// Store or replace an introspection result.
    async fn put(
        &self,
        token_hash: &str,
        active: bool,
        sub: Option<&str>,
        scope: Option<&str>,
        exp: Option<time::OffsetDateTime>,
    ) -> Result<(), DbError>;

    /// Remove a cached entry, e.g. after revocation.
    async fn remove(&self, token_hash: &str) -> Result<(), DbError>;
}

#[derive(Clone)]
pub struct PgTokenIntrospectionCache {
    pool: DbPool,
}

impl PgTokenIntrospectionCache {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TokenIntrospectionCache for PgTokenIntrospectionCache {
    async fn get(
        &self,
        token_hash: &str,
        max_age: time::Duration,
    ) -> Result<Option<TokenIntrospectionRow>, DbError> {
        let row = sqlx::query_as::<_, TokenIntrospectionRow>(
            "SELECT token_hash, active, sub, scope, exp, cached_at \
             FROM token_introspection_cache \
             WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };

        let now = time::OffsetDateTime::now_utc();
        if row.cached_at + max_age < now {
            return Ok(None);
        }

        if let Some(exp) = row.exp
            && exp < now
        {
            return Ok(None);
        }

        Ok(Some(row))
    }

    async fn put(
        &self,
        token_hash: &str,
        active: bool,
        sub: Option<&str>,
        scope: Option<&str>,
        exp: Option<time::OffsetDateTime>,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO token_introspection_cache \
             (token_hash, active, sub, scope, exp, cached_at) \
             VALUES ($1, $2, $3, $4, $5, NOW()) \
             ON CONFLICT (token_hash) DO UPDATE SET \
             active = EXCLUDED.active, \
             sub = EXCLUDED.sub, \
             scope = EXCLUDED.scope, \
             exp = EXCLUDED.exp, \
             cached_at = NOW()",
        )
        .bind(token_hash)
        .bind(active)
        .bind(sub)
        .bind(scope)
        .bind(exp)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove(&self, token_hash: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM token_introspection_cache WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TokenIntrospectionRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            token_hash: row.try_get("token_hash")?,
            active: row.try_get("active")?,
            sub: row.try_get("sub")?,
            scope: row.try_get("scope")?,
            exp: row.try_get("exp")?,
            cached_at: row.try_get("cached_at")?,
        })
    }
}
