#![allow(dead_code)]

use std::sync::{Arc, Once};
use std::time::Duration;

use async_trait::async_trait;
use sqlx::Connection;
use sso_gateway::auth::{IntrospectionResult, TokenIntrospector};
use sso_gateway::db::SessionStore;
use testcontainers::{
    ContainerAsync, CopyTargetOptions, GenericImage, ImageExt,
    core::{ContainerPort, WaitFor, ports::IntoContainerPort},
    runners::AsyncRunner,
};

static CLEANUP: Once = Once::new();
const START_RETRIES: usize = 3;

/// Retry a fallible async operation a few times with exponential backoff.
/// Rootless Docker can race on ephemeral port allocation when many containers
/// start concurrently; a short retry usually finds a free port.
async fn retry_start<F, Fut, T, E>(label: &str, f: F) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut last_err = None;
    for attempt in 1..=START_RETRIES {
        match f().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_err = Some(err);
                if attempt < START_RETRIES {
                    let delay = Duration::from_millis(500 * attempt as u64);
                    eprintln!(
                        "warning: {label} container start failed (attempt {attempt}), retrying after {delay:?}..."
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    // SAFETY: last_err is always Some because the loop runs at least once and
    // only returns early on Ok.
    Err(last_err.unwrap())
}

/// Remove containers left behind by previous testcontainers runs.
///
/// testcontainers normally drops containers when the `ContainerAsync` value is
/// dropped, but startup failures (e.g. RootlessKit port-binding races) can leak
/// the created container before a handle exists. Running this once per test
/// binary before starting new containers prevents those leftovers from causing
/// cascading port conflicts.
fn cleanup_lingering_testcontainers() {
    CLEANUP.call_once(|| {
        let output = std::process::Command::new("docker")
            .args([
                "ps",
                "-aq",
                "-f",
                "label=org.testcontainers.managed-by=testcontainers",
            ])
            .output();

        let ids = match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
            Err(err) => {
                eprintln!("warning: failed to list lingering containers: {err}");
                return;
            }
        };

        for id in ids.lines().map(str::trim).filter(|s| !s.is_empty()) {
            if let Err(err) = std::process::Command::new("docker")
                .args(["rm", "-f", id])
                .output()
            {
                eprintln!("warning: failed to remove lingering container {id}: {err}");
            }
        }
    });
}

fn ensure_test_pool_defaults() {
    // Integration tests use testcontainers with sslmode=disable. Set forgiving
    // defaults so the pool does not time out under concurrent test load.
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

pub async fn start_postgres()
-> Result<(ContainerAsync<GenericImage>, String), Box<dyn std::error::Error + Send + Sync>> {
    ensure_test_pool_defaults();
    cleanup_lingering_testcontainers();
    // RootlessKit port release is asynchronous; give the previous container a
    // moment to fully disappear before allocating a new random host port.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let container = retry_start("postgres", || async {
        GenericImage::new("postgres", "17")
            .with_exposed_port(ContainerPort::Tcp(5432))
            .with_wait_for(WaitFor::message_on_stdout(
                "database system is ready to accept connections",
            ))
            .with_mapped_port(0, 5432.tcp())
            .with_env_var("POSTGRES_USER", "ory")
            .with_env_var("POSTGRES_PASSWORD", "ory")
            .with_env_var("POSTGRES_DB", "ory")
            .with_startup_timeout(Duration::from_secs(120))
            .start()
            .await
    })
    .await?;

    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(5432.tcp()).await?;
    let url = format!("postgres://ory:ory@{host}:{port}/ory?sslmode=disable");

    wait_for_postgres(&url, Duration::from_secs(60)).await?;

    Ok((container, url))
}

pub async fn start_hydra()
-> Result<(ContainerAsync<GenericImage>, String, String), Box<dyn std::error::Error + Send + Sync>>
{
    start_hydra_with_issuer("http://localhost:4444").await
}

pub async fn start_hydra_with_issuer(
    self_issuer: &str,
) -> Result<(ContainerAsync<GenericImage>, String, String), Box<dyn std::error::Error + Send + Sync>>
{
    cleanup_lingering_testcontainers();
    tokio::time::sleep(Duration::from_millis(500)).await;

    const PUBLIC_PORT: u16 = 4444;
    const ADMIN_PORT: u16 = 4445;
    let self_issuer = self_issuer.to_string();

    let container = retry_start("hydra", || {
        let self_issuer = self_issuer.clone();
        async move {
            GenericImage::new("oryd/hydra", "v25.4.0")
                .with_exposed_port(ContainerPort::Tcp(PUBLIC_PORT))
                .with_exposed_port(ContainerPort::Tcp(ADMIN_PORT))
                .with_wait_for(WaitFor::message_on_either_std("Successfully applied"))
                .with_mapped_port(0, PUBLIC_PORT.tcp())
                .with_mapped_port(0, ADMIN_PORT.tcp())
                .with_cmd(["serve", "all", "--dev"])
                .with_env_var("DSN", "memory")
                .with_env_var("SECRETS_SYSTEM", "some-long-secret-key-for-tests")
                .with_env_var("URLS_SELF_ISSUER", &self_issuer)
                .with_startup_timeout(Duration::from_secs(120))
                .start()
                .await
        }
    })
    .await?;

    let host = container.get_host().await?.to_string();
    let public_port = container.get_host_port_ipv4(PUBLIC_PORT.tcp()).await?;
    let admin_port = container.get_host_port_ipv4(ADMIN_PORT.tcp()).await?;
    let public_url = format!("http://{host}:{public_port}");
    let admin_url = format!("http://{host}:{admin_port}");

    wait_for_ok(format!("{admin_url}/health/ready")).await?;

    Ok((container, admin_url, public_url))
}

const KRATOS_CONFIG: &str = r#"version: v0.13.0
identity:
  default_schema_id: default
  schemas:
    - id: default
      url: base64://eyIkaWQiOiJodHRwczovL3NjaGVtYXMub3J5LnNoL3ByZXNldHMva3JhdG9zL3F1aWNrc3RhcnQvZW1haWwtcGFzc3dvcmQvaWRlbnRpdHkuc2NoZW1hLmpzb24iLCIkc2NoZW1hIjoiaHR0cDovL2pzb24tc2NoZW1hLm9yZy9kcmFmdC0wNy9zY2hlbWEjIiwidGl0bGUiOiJQZXJzb24iLCJ0eXBlIjoib2JqZWN0IiwicHJvcGVydGllcyI6eyJ0cmFpdHMiOnsidHlwZSI6Im9iamVjdCIsInByb3BlcnRpZXMiOnsiZW1haWwiOnsidHlwZSI6InN0cmluZyIsImZvcm1hdCI6ImVtYWlsIiwidGl0bGUiOiJFLU1haWwiLCJvcnkuc2gva3JhdG9zIjp7ImNyZWRlbnRpYWxzIjp7InBhc3N3b3JkIjp7ImlkZW50aWZpZXIiOnRydWV9fSwicmVjb3ZlcnkiOnsidmlhIjoiZW1haWwifSwidmVyaWZpY2F0aW9uIjp7InZpYSI6ImVtYWlsIn19fSwidXNlck5hbWUiOnsidHlwZSI6InN0cmluZyJ9LCJuYW1lIjp7InR5cGUiOiJvYmplY3QifSwiYWN0aXZlIjp7InR5cGUiOiJib29sZWFuIn0sInRlbmFudF9pZCI6eyJ0eXBlIjoic3RyaW5nIn19LCJyZXF1aXJlZCI6WyJlbWFpbCJdLCJhZGRpdGlvbmFsUHJvcGVydGllcyI6ZmFsc2V9fX0=
serve:
  public:
    base_url: http://localhost:4433/
  admin:
    base_url: http://localhost:4434/
selfservice:
  default_browser_return_url: http://localhost:4433/
  methods:
    password:
      enabled: true
      config:
        haveibeenpwned_enabled: false
  flows:
    registration:
      after:
        password:
          hooks:
            - hook: session
"#;

const KETO_CONFIG: &str = r#"dsn: memory

namespaces:
  - id: 0
    name: app
  - id: 1
    name: scim_group
  - id: 2
    name: entitlements

serve:
  read:
    host: 0.0.0.0
    port: 4466
  write:
    host: 0.0.0.0
    port: 4467
  metrics:
    host: 0.0.0.0
    port: 4468
"#;

pub async fn start_keto()
-> Result<(ContainerAsync<GenericImage>, String, String), Box<dyn std::error::Error + Send + Sync>>
{
    cleanup_lingering_testcontainers();
    tokio::time::sleep(Duration::from_millis(500)).await;

    const READ_PORT: u16 = 4466;
    const WRITE_PORT: u16 = 4467;

    let config_bytes = KETO_CONFIG.as_bytes().to_vec();
    let container = retry_start("keto", || {
        let config_bytes = config_bytes.clone();
        async move {
            GenericImage::new("oryd/keto", "v26.2.0")
                .with_exposed_port(ContainerPort::Tcp(READ_PORT))
                .with_exposed_port(ContainerPort::Tcp(WRITE_PORT))
                .with_wait_for(WaitFor::message_on_either_std("Successfully applied"))
                .with_mapped_port(0, READ_PORT.tcp())
                .with_mapped_port(0, WRITE_PORT.tcp())
                .with_copy_to(CopyTargetOptions::new("/home/ory/keto.yml"), config_bytes)
                .with_cmd(["serve", "-c", "/home/ory/keto.yml"])
                .with_env_var("DSN", "memory")
                .with_startup_timeout(Duration::from_secs(120))
                .start()
                .await
        }
    })
    .await?;

    let host = container.get_host().await?.to_string();
    let read_port = container.get_host_port_ipv4(READ_PORT.tcp()).await?;
    let write_port = container.get_host_port_ipv4(WRITE_PORT.tcp()).await?;
    let read_url = format!("http://{host}:{read_port}");
    let write_url = format!("http://{host}:{write_port}");

    wait_for_ok(format!("{read_url}/health/ready")).await?;

    Ok((container, read_url, write_url))
}

pub async fn start_openfga()
-> Result<(ContainerAsync<GenericImage>, String), Box<dyn std::error::Error + Send + Sync>> {
    cleanup_lingering_testcontainers();
    tokio::time::sleep(Duration::from_millis(500)).await;

    const HTTP_PORT: u16 = 8080;

    let container = retry_start("openfga", || async move {
        GenericImage::new("openfga/openfga", "v1.8.3")
            .with_exposed_port(ContainerPort::Tcp(HTTP_PORT))
            .with_wait_for(WaitFor::message_on_either_std("starting openfga service"))
            .with_mapped_port(0, HTTP_PORT.tcp())
            .with_cmd(["run"])
            .with_startup_timeout(Duration::from_secs(120))
            .start()
            .await
    })
    .await?;

    let host = container.get_host().await?.to_string();
    let http_port = container.get_host_port_ipv4(HTTP_PORT.tcp()).await?;
    let url = format!("http://{host}:{http_port}");

    wait_for_ok(format!("{url}/healthz")).await?;

    Ok((container, url))
}

pub async fn start_kratos()
-> Result<(ContainerAsync<GenericImage>, String, String), Box<dyn std::error::Error + Send + Sync>>
{
    cleanup_lingering_testcontainers();
    tokio::time::sleep(Duration::from_millis(500)).await;

    const PUBLIC_PORT: u16 = 4433;
    const ADMIN_PORT: u16 = 4434;

    let config_bytes = KRATOS_CONFIG.as_bytes().to_vec();
    let container = retry_start("kratos", || {
        let config_bytes = config_bytes.clone();
        async move {
            GenericImage::new("oryd/kratos", "v25.4.0")
                .with_exposed_port(ContainerPort::Tcp(PUBLIC_PORT))
                .with_exposed_port(ContainerPort::Tcp(ADMIN_PORT))
                .with_wait_for(WaitFor::message_on_either_std(
                    "Starting the public httpd on: 0.0.0.0:4433",
                ))
                .with_mapped_port(0, PUBLIC_PORT.tcp())
                .with_mapped_port(0, ADMIN_PORT.tcp())
                .with_copy_to(CopyTargetOptions::new("/home/ory/kratos.yml"), config_bytes)
                .with_cmd(["serve", "-c", "/home/ory/kratos.yml", "--dev"])
                .with_env_var("DSN", "memory")
                .with_startup_timeout(Duration::from_secs(120))
                .start()
                .await
        }
    })
    .await?;

    let host = container.get_host().await?.to_string();
    let public_port = container.get_host_port_ipv4(PUBLIC_PORT.tcp()).await?;
    let admin_port = container.get_host_port_ipv4(ADMIN_PORT.tcp()).await?;
    let public_url = format!("http://{host}:{public_port}");
    let admin_url = format!("http://{host}:{admin_port}");

    wait_for_ok(format!("{admin_url}/health/ready")).await?;

    Ok((container, admin_url, public_url))
}

async fn wait_for_ok(url: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!("health endpoint did not become ready: {url}").into());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

async fn wait_for_postgres(
    url: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
                    return Err(err.into());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub const TEST_TOKEN: &str = "integration-test-token";
pub const TEST_SUBJECT: &str = "integration-test-subject";

/// Test introspector that always returns an active token for `TEST_SUBJECT`.
#[derive(Clone, Default)]
pub struct TestIntrospector;

#[async_trait]
impl TokenIntrospector for TestIntrospector {
    async fn introspect(
        &self,
        token: &str,
    ) -> Result<IntrospectionResult, sso_gateway::auth::AuthError> {
        if token != TEST_TOKEN {
            return Ok(IntrospectionResult {
                active: false,
                sub: None,
                scope: vec![],
                exp: None,
                authentication_methods: vec![],
            });
        }
        Ok(IntrospectionResult {
            active: true,
            sub: Some(TEST_SUBJECT.into()),
            scope: vec![
                "openid".to_string(),
                "tenant:admin".to_string(),
                "tenant:read".to_string(),
                "identity:admin".to_string(),
                "identity:read".to_string(),
                "scim:admin".to_string(),
                "scim:read".to_string(),
                "permission:admin".to_string(),
                "permission:read".to_string(),
                "application:admin".to_string(),
                "application:read".to_string(),
            ],
            exp: None,
            authentication_methods: vec![],
        })
    }
}

/// Return a boxed test introspector for use in the shared auth middleware.
pub fn test_introspector() -> Arc<dyn TokenIntrospector> {
    Arc::new(TestIntrospector)
}

/// Test session store that considers every session active.
#[derive(Clone, Default)]
pub struct TestSessionStore;

#[async_trait]
impl SessionStore for TestSessionStore {
    async fn create(
        &self,
        _session_id: &str,
        _sub: &str,
        _tenant_id: &str,
        _amr: &str,
        _expires_at: time::OffsetDateTime,
    ) -> Result<(), sso_gateway::db::DbError> {
        Ok(())
    }

    async fn is_active(&self, _session_id: &str) -> Result<bool, sso_gateway::db::DbError> {
        Ok(true)
    }

    async fn revoke(&self, _session_id: &str) -> Result<(), sso_gateway::db::DbError> {
        Ok(())
    }

    async fn revoke_all_for_subject(&self, _sub: &str) -> Result<(), sso_gateway::db::DbError> {
        Ok(())
    }
}

/// Return a boxed test session store for use in the shared auth middleware.
pub fn test_session_store() -> Arc<dyn SessionStore> {
    Arc::new(TestSessionStore)
}

/// Insert an id_mapping so the shared auth middleware can resolve
/// `TEST_SUBJECT` to the given tenant.
pub async fn bootstrap_test_subject_mapping(pool: &sqlx::PgPool, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO id_mappings (id, tenant_id, backend, public_id, ory_global_id) \
         VALUES ($1, $2, 'hydra', $3, $3)",
    )
    .bind(ulid::Ulid::new().to_string())
    .bind(tenant_id)
    .bind(TEST_SUBJECT)
    .execute(pool)
    .await
    .expect("test subject mapping should be created");
}
