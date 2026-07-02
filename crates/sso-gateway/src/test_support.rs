#![cfg(test)]

use std::time::Duration;

use sqlx::{Connection as _, PgPool, postgres::PgPoolOptions};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ContainerPort, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::sync::OnceCell;

static CONTAINER: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static URL: OnceCell<String> = OnceCell::const_new();

fn ensure_lima_docker() {
    // Force testcontainers to talk to the lima-docker context's socket unless
    // the caller has already pinned a Docker endpoint.
    if std::env::var("DOCKER_HOST").is_err() {
        unsafe {
            std::env::set_var(
                "DOCKER_HOST",
                "unix:///Users/sienna/.lima/docker/sock/docker.sock",
            );
        }
    }
    // Tests use testcontainers with sslmode=disable and need forgiving pool
    // defaults to avoid timeouts on the shared Postgres container.
    if std::env::var("DATABASE_SSL_REQUIRED").is_err() {
        unsafe { std::env::set_var("DATABASE_SSL_REQUIRED", "false") };
    }
    if std::env::var("DATABASE_MAX_CONNECTIONS").is_err() {
        unsafe { std::env::set_var("DATABASE_MAX_CONNECTIONS", "5") };
    }
    if std::env::var("DATABASE_ACQUIRE_TIMEOUT_SECONDS").is_err() {
        unsafe { std::env::set_var("DATABASE_ACQUIRE_TIMEOUT_SECONDS", "30") };
    }
}

async fn container_url() -> &'static str {
    ensure_lima_docker();
    let _container = CONTAINER
        .get_or_init(|| async {
            let container = GenericImage::new("postgres", "17")
                .with_exposed_port(ContainerPort::Tcp(5432))
                .with_wait_for(WaitFor::message_on_stdout(
                    "database system is ready to accept connections",
                ))
                .with_mapped_port(0, 5432_u16.tcp())
                .with_env_var("POSTGRES_USER", "ory")
                .with_env_var("POSTGRES_PASSWORD", "ory")
                .with_env_var("POSTGRES_DB", "ory")
                .with_startup_timeout(Duration::from_secs(120))
                .start()
                .await
                .expect("failed to start postgres container");

            let host = container
                .get_host()
                .await
                .expect("container host")
                .to_string();
            let port = container
                .get_host_port_ipv4(5432_u16.tcp())
                .await
                .expect("container port");
            let url = format!("postgres://ory:ory@{host}:{port}/ory?sslmode=disable");

            wait_for_postgres(&url, Duration::from_secs(60))
                .await
                .expect("postgres did not become ready");

            // Run migrations once on the shared container.
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("failed to connect migrations pool");
            sqlx::migrate!("../../migrations")
                .run(&pool)
                .await
                .expect("failed to run migrations");

            URL.set(url).expect("url already set");

            container
        })
        .await;
    URL.get().expect("url not set")
}

/// Returns the JDBC-style Postgres URL for the shared testcontainer.
pub async fn postgres_url() -> &'static str {
    container_url().await
}

/// Returns a fresh, connected Postgres pool backed by the shared testcontainer.
/// Callers get their own pool so concurrent tests cannot starve each other.
pub async fn postgres_pool() -> PgPool {
    let url = container_url().await;
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(30))
        .connect(url)
        .await
        .expect("failed to create test pool")
}

/// Insert a bare tenant row needed as a foreign key for other tables.
pub async fn create_test_tenant(pool: &PgPool, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(format!("slug-{tenant_id}"))
    .bind("Test Tenant")
    .execute(pool)
    .await
    .expect("insert tenant");
}

async fn wait_for_postgres(url: &str, timeout: Duration) -> Result<(), sqlx::Error> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match sqlx::postgres::PgConnection::connect(url).await {
            Ok(mut conn) => {
                if sqlx::query("SELECT 1").execute(&mut conn).await.is_ok() {
                    return Ok(());
                }
            }
            Err(err) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(err);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
