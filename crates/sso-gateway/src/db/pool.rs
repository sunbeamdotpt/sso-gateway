use sqlx::{Pool, Postgres, migrate::MigrateDatabase};
use tracing::info;

use super::error::DbError;

pub type DbPool = Pool<Postgres>;

pub async fn create_pool(database_url: &str) -> Result<DbPool, sqlx::Error> {
    if !Postgres::database_exists(database_url)
        .await
        .unwrap_or(false)
    {
        Postgres::create_database(database_url).await?;
    }

    let pool = Pool::<Postgres>::connect(database_url).await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;
    Ok(pool)
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
