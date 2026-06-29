#![allow(dead_code)]

use std::time::Duration;

use testcontainers::{
    ContainerAsync, CopyTargetOptions, GenericImage, ImageExt,
    core::{ContainerPort, WaitFor, ports::IntoContainerPort},
    runners::AsyncRunner,
};

const KRATOS_CONFIG: &str = r#"version: v0.13.0
identity:
  default_schema_id: default
  schemas:
    - id: default
      url: base64://eyIkaWQiOiAiaHR0cHM6Ly9zY2hlbWFzLm9yeS5zaC9wcmVzZXRzL2tyYXRvcy9xdWlja3N0YXJ0L2VtYWlsLXBhc3N3b3JkL2lkZW50aXR5LnNjaGVtYS5qc29uIiwgIiRzY2hlbWEiOiAiaHR0cDovL2pzb24tc2NoZW1hLm9yZy9kcmFmdC0wNy9zY2hlbWEjIiwgInRpdGxlIjogIlBlcnNvbiIsICJ0eXBlIjogIm9iamVjdCIsICJwcm9wZXJ0aWVzIjogeyJ0cmFpdHMiOiB7InR5cGUiOiAib2JqZWN0IiwgInByb3BlcnRpZXMiOiB7ImVtYWlsIjogeyJ0eXBlIjogInN0cmluZyIsICJmb3JtYXQiOiAiZW1haWwiLCAidGl0bGUiOiAiRS1NYWlsIiwgIm9yeS5zaC9rcmF0b3MiOiB7ImNyZWRlbnRpYWxzIjogeyJwYXNzd29yZCI6IHsiaWRlbnRpZmllciI6IHRydWV9fSwgInJlY292ZXJ5IjogeyJ2aWEiOiAiZW1haWwifSwgInZlcmlmaWNhdGlvbiI6IHsidmlhIjogImVtYWlsIn19fX0sICJyZXF1aXJlZCI6IFsiZW1haWwiXSwgImFkZGl0aW9uYWxQcm9wZXJ0aWVzIjogZmFsc2V9fX0=
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
"#;

const KETO_CONFIG: &str = r#"dsn: memory

namespaces:
  - id: 0
    name: app

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

pub async fn start_hydra()
-> Result<(ContainerAsync<GenericImage>, String, String), Box<dyn std::error::Error + Send + Sync>>
{
    const PUBLIC_PORT: u16 = 4444;
    const ADMIN_PORT: u16 = 4445;

    let container = GenericImage::new("oryd/hydra", "v25.4.0")
        .with_exposed_port(ContainerPort::Tcp(PUBLIC_PORT))
        .with_exposed_port(ContainerPort::Tcp(ADMIN_PORT))
        .with_wait_for(WaitFor::message_on_either_std("Successfully applied"))
        .with_mapped_port(0, PUBLIC_PORT.tcp())
        .with_mapped_port(0, ADMIN_PORT.tcp())
        .with_cmd(["serve", "all", "--dev"])
        .with_env_var("DSN", "memory")
        .with_env_var("SECRETS_SYSTEM", "some-long-secret-key-for-tests")
        .with_env_var("URLS_SELF_ISSUER", "http://localhost:4444")
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .await?;

    let host = container.get_host().await?.to_string();
    let public_port = container.get_host_port_ipv4(PUBLIC_PORT.tcp()).await?;
    let admin_port = container.get_host_port_ipv4(ADMIN_PORT.tcp()).await?;
    let public_url = format!("http://{host}:{public_port}");
    let admin_url = format!("http://{host}:{admin_port}");

    wait_for_ok(format!("{admin_url}/health/ready")).await?;

    Ok((container, admin_url, public_url))
}

pub async fn start_kratos()
-> Result<(ContainerAsync<GenericImage>, String, String), Box<dyn std::error::Error + Send + Sync>>
{
    const PUBLIC_PORT: u16 = 4433;
    const ADMIN_PORT: u16 = 4434;

    let config_bytes = KRATOS_CONFIG.as_bytes().to_vec();
    let container = GenericImage::new("oryd/kratos", "v25.4.0")
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
        .await?;

    let host = container.get_host().await?.to_string();
    let public_port = container.get_host_port_ipv4(PUBLIC_PORT.tcp()).await?;
    let admin_port = container.get_host_port_ipv4(ADMIN_PORT.tcp()).await?;
    let public_url = format!("http://{host}:{public_port}");
    let admin_url = format!("http://{host}:{admin_port}");

    wait_for_ok(format!("{admin_url}/health/ready")).await?;

    Ok((container, admin_url, public_url))
}

pub async fn start_keto()
-> Result<(ContainerAsync<GenericImage>, String, String), Box<dyn std::error::Error + Send + Sync>>
{
    const READ_PORT: u16 = 4466;
    const WRITE_PORT: u16 = 4467;

    let config_bytes = KETO_CONFIG.as_bytes().to_vec();
    let container = GenericImage::new("oryd/keto", "v26.2.0")
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
        .await?;

    let host = container.get_host().await?.to_string();
    let read_port = container.get_host_port_ipv4(READ_PORT.tcp()).await?;
    let write_port = container.get_host_port_ipv4(WRITE_PORT.tcp()).await?;
    let read_url = format!("http://{host}:{read_port}");
    let write_url = format!("http://{host}:{write_port}");

    wait_for_ok(format!("{read_url}/health/ready")).await?;

    Ok((container, read_url, write_url))
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
