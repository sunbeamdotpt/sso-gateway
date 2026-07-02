use std::str::FromStr;
use std::time::Duration;

use sqlx::{
    Pool, Postgres,
    migrate::MigrateDatabase,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tracing::info;

use super::error::DbError;

pub type DbPool = Pool<Postgres>;

/// Build a PostgreSQL connection pool from `database_url` using the gateway's
/// configured pool and TLS options.
///
/// `ssl_required` mirrors the `database_ssl_required` configuration value. When
/// true, a URL containing `sslmode=disable` is rejected so the gateway cannot
/// silently connect without TLS in production.
pub async fn create_pool(
    database_url: &str,
    ssl_required: bool,
) -> Result<DbPool, sqlx::Error> {
    if !Postgres::database_exists(database_url)
        .await
        .unwrap_or(false)
    {
        Postgres::create_database(database_url).await?;
    }

    let options = pool_options(database_url, ssl_required)?;
    let pool = PgPoolOptions::new()
        .max_connections(options.max_connections)
        .acquire_timeout(options.acquire_timeout)
        .idle_timeout(options.idle_timeout)
        .max_lifetime(options.max_lifetime)
        .after_connect(move |conn, _meta| {
            let statement_timeout_ms = options.statement_timeout.as_millis() as i64;
            let sql = format!("SET statement_timeout = {statement_timeout_ms}");
            Box::pin(async move {
                sqlx::query(&sql).execute(conn).await?;
                Ok(())
            })
        })
        .connect_with(options.connect_options)
        .await?;

    sqlx::migrate!("../../migrations").run(&pool).await?;
    Ok(pool)
}

struct PoolOptions {
    connect_options: PgConnectOptions,
    max_connections: u32,
    acquire_timeout: Duration,
    idle_timeout: Duration,
    max_lifetime: Duration,
    statement_timeout: Duration,
}

fn pool_options(database_url: &str, ssl_required: bool) -> Result<PoolOptions, sqlx::Error> {
    if ssl_required && database_url.contains("sslmode=disable") {
        return Err(sqlx::Error::Configuration(
            "DATABASE_URL uses sslmode=disable but DATABASE_SSL_REQUIRED is true".into(),
        ));
    }

    let connect_options = PgConnectOptions::from_str(database_url)?;

    let max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(25);
    let acquire_timeout_seconds = std::env::var("DATABASE_ACQUIRE_TIMEOUT_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let idle_timeout_seconds = std::env::var("DATABASE_IDLE_TIMEOUT_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);
    let max_lifetime_seconds = std::env::var("DATABASE_MAX_LIFETIME_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1800);
    let statement_timeout_seconds = std::env::var("DATABASE_STATEMENT_TIMEOUT_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    Ok(PoolOptions {
        connect_options,
        max_connections,
        acquire_timeout: Duration::from_secs(acquire_timeout_seconds),
        idle_timeout: Duration::from_secs(idle_timeout_seconds),
        max_lifetime: Duration::from_secs(max_lifetime_seconds),
        statement_timeout: Duration::from_secs(statement_timeout_seconds),
    })
}

pub async fn bootstrap_system_tenant(
    pool: &DbPool,
    system_tenant_ulid: &str,
) -> Result<String, DbError> {
    let existing: Option<String> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE id = $1 AND is_system = TRUE")
            .bind(system_tenant_ulid)
            .fetch_optional(pool)
            .await?;

    if let Some(id) = existing {
        info!("system tenant already bootstrapped: {}", id);
        return Ok(id);
    }

    sqlx::query(
        "INSERT INTO tenants (id, slug, display_name, is_system, settings) VALUES ($1, $2, $3, TRUE, $4)",
    )
    .bind(system_tenant_ulid)
    .bind("system")
    .bind("System")
    .bind(sqlx::types::Json(serde_json::json!({})))
    .execute(pool)
    .await?;

    info!("bootstrapped system tenant: {}", system_tenant_ulid);
    Ok(system_tenant_ulid.to_string())
}

#[cfg(test)]
mod tests {
    use ulid::Ulid;

    use super::*;
    use crate::test_support::{postgres_pool, postgres_url};

    fn db_url_with_name(base: &str, db_name: &str) -> String {
        // base looks like postgres://user:pass@host:port/ory?sslmode=disable
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
    async fn create_pool_creates_and_migrates_database() {
        let base = postgres_url().await;
        let url = db_url_with_name(
            base,
            &format!("ory_pool_{}", Ulid::new().to_string().to_lowercase()),
        );
        let pool = create_pool(&url, false).await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tenants")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.0, 0);
    }

    #[tokio::test]
    async fn bootstrap_system_tenant_creates_system_tenant() {
        let pool = postgres_pool().await;
        let system_id = Ulid::new().to_string();
        let id = bootstrap_system_tenant(&pool, &system_id).await.unwrap();
        assert_eq!(id, system_id);

        let slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
            .bind(&system_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(slug, "system");

        // Idempotent second call returns existing id.
        let id2 = bootstrap_system_tenant(&pool, &system_id).await.unwrap();
        assert_eq!(id2, system_id);
    }

    #[test]
    fn pool_options_reject_sslmode_disable_when_required() {
        let result = pool_options("postgres://u:p@localhost/db?sslmode=disable", true);
        assert!(result.is_err());
    }

    #[test]
    fn pool_options_accept_sslmode_disable_when_not_required() {
        let result = pool_options("postgres://u:p@localhost/db?sslmode=disable", false);
        assert!(result.is_ok());
    }
}
