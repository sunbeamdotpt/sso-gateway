use std::time::Duration;

use sso_gateway::{
    app::build_app,
    config::Config,
    db::{PgSamlIdpKeyStore, PgSamlProviderStore, PgSamlSpClientStore, create_pool},
};
use sunbeam_g2v::server::axum::bind_random_port;
use testcontainers::ContainerAsync;
use testcontainers::GenericImage;

#[path = "../support/mod.rs"]
mod shared_support;

/// A running gateway instance together with its backing containers and HTTP client.
pub struct Gateway {
    pub base_url: String,
    pub system_tenant_ulid: String,
    pub admin_token: String,
    pub http: reqwest::Client,
    pub hydra_admin_url: String,
    pub hydra_public_url: String,
    pub kratos_public_url: String,
    pool: sqlx::PgPool,
    shutdown: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
    #[allow(dead_code)]
    _pg: ContainerAsync<GenericImage>,
    #[allow(dead_code)]
    _hydra: ContainerAsync<GenericImage>,
    #[allow(dead_code)]
    _kratos: ContainerAsync<GenericImage>,
    #[allow(dead_code)]
    _keto: ContainerAsync<GenericImage>,
}

impl Gateway {
    /// Start Postgres, Hydra, Kratos, Keto, build the full gateway app, and serve it on a random port.
    pub async fn start() -> Self {
        let (_pg, database_url) = shared_support::start_postgres()
            .await
            .expect("postgres should start");
        let (_kratos, kratos_admin_url, kratos_public_url) = shared_support::start_kratos()
            .await
            .expect("kratos should start");
        let (_keto, keto_read_url, keto_write_url) = shared_support::start_keto()
            .await
            .expect("keto should start");

        let pool = create_pool(&database_url, false)
            .await
            .expect("database pool should be created");

        let system_tenant_ulid = ulid::Ulid::new().to_string();

        // Bind the gateway port before starting Hydra so Hydra can be told to
        // issue tokens with the gateway's public URL as the issuer.
        let (listener, addr) = bind_random_port("127.0.0.1")
            .await
            .expect("random port should bind");
        let public_base_url = format!("http://{addr}");

        let (_hydra, hydra_admin_url, hydra_public_url) =
            shared_support::start_hydra_with_issuer(&public_base_url)
                .await
                .expect("hydra should start");

        let config = Config {
            bind_addr: addr,
            system_tenant_ulid: system_tenant_ulid.clone(),
            database_url,
            hydra_admin_url: hydra_admin_url.clone(),
            hydra_public_url: hydra_public_url.clone(),
            kratos_admin_url: kratos_admin_url.clone(),
            kratos_public_url: kratos_public_url.clone(),
            kratos_default_schema_id: "default".to_string(),
            permissions_backend: sso_gateway::config::PermissionsBackend::Keto,
            keto_read_url,
            keto_write_url,
            openfga_url: "http://localhost:1".to_string(),
            public_base_url: public_base_url.clone(),
            ui_public_url: public_base_url.clone(),
            saml_sp_private_key_pem_path: None,
            saml_sp_certificate_pem_path: None,
            saml_idp_entity_id: Some("https://gateway.example.com/saml/idp".to_string()),
            saml_request_ttl_seconds: 900,
            saml_require_signed_assertions: true,
            saml_require_signed_responses: false,
            registration_enabled: false,
            allowed_return_to_hosts: vec!["app.example.com".to_string()],
            system_bootstrap_client_id: Some("integration-test-admin-client".to_string()),
            system_bootstrap_client_secret: Some("integration-test-admin-secret".to_string()),
            state_cookie_secret: "conformance-test-secret-key-at-least-32-bytes-long".into(),
            cookie_secure: true,
            cookie_samesite: "Lax".to_string(),
            saml_idp_key_encryption_key: Some(vec![0u8; 32]),
            tenant_connection_encryption_key: None,
            database_ssl_required: false,
            database_max_connections: 25,
            database_acquire_timeout_seconds: 10,
            database_idle_timeout_seconds: 600,
            database_max_lifetime_seconds: 1800,
            database_statement_timeout_seconds: 30,
            token_introspection_cache_ttl_seconds: 30,
            session_ttl_seconds: 86400,
            nats_url: None,
            agent_act_token_ttl_seconds: 3600,
            agent_cache_ttl_seconds: 5,
            public_rate_limit_requests: 100,
            public_rate_limit_window_seconds: 60,
            self_service_paths: sso_gateway::config::SelfServicePaths::default(),
        };

        let app = build_app(&config, pool.clone())
            .await
            .expect("gateway app should build");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("gateway should serve");
        });

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("http client should build");

        wait_for_ok(
            &http,
            &format!("{public_base_url}/.well-known/openid-configuration"),
        )
        .await
        .expect("gateway health endpoint should be ready");

        let admin_token = fetch_bootstrap_token(
            &http,
            &public_base_url,
            config.system_bootstrap_client_id.as_deref().unwrap_or(""),
            config
                .system_bootstrap_client_secret
                .as_deref()
                .unwrap_or(""),
        )
        .await
        .expect("bootstrap admin token should be fetched");

        Self {
            base_url: public_base_url,
            system_tenant_ulid,
            admin_token,
            http,
            hydra_admin_url,
            hydra_public_url,
            kratos_public_url,
            pool,
            shutdown: shutdown_tx,
            handle,
            _pg,
            _hydra,
            _kratos,
            _keto,
        }
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }

    /// Create an OAuth2/OIDC application and return the created resource as JSON.
    pub async fn create_application(
        &self,
        name: &str,
        redirect_uris: &[&str],
        grant_types: &[&str],
        response_types: &[&str],
        scopes: &[&str],
    ) -> serde_json::Value {
        let resp = self
            .http
            .post(format!(
                "{}/iam.v1.ApplicationService/CreateApplication",
                self.base_url
            ))
            .header("authorization", format!("Bearer {}", self.admin_token))
            .header("content-type", "application/json")
            .json(&serde_json::json!({
                "name": name,
                "redirectUris": redirect_uris,
                "grantTypes": grant_types,
                "responseTypes": response_types,
                "scope": scopes,
                "tokenEndpointAuthMethod": "client_secret_post"
            }))
            .send()
            .await
            .expect("create application request should succeed");

        assert!(
            resp.status().is_success(),
            "create application failed: {}",
            resp.text().await.unwrap_or_default()
        );

        resp.json()
            .await
            .expect("application response should be json")
    }

    /// Rotate an application's secret and return `(client_id, client_secret)`.
    pub async fn rotate_secret(&self, app_id: &str) -> (String, String) {
        let resp = self
            .http
            .post(format!(
                "{}/iam.v1.ApplicationService/RotateSecret",
                self.base_url
            ))
            .header("authorization", format!("Bearer {}", self.admin_token))
            .header("content-type", "application/json")
            .json(&serde_json::json!({ "id": app_id }))
            .send()
            .await
            .expect("rotate secret request should succeed");

        assert!(
            resp.status().is_success(),
            "rotate secret failed: {}",
            resp.text().await.unwrap_or_default()
        );

        let body: serde_json::Value = resp.json().await.expect("rotate secret should be json");
        let client_id = body["clientId"]
            .as_str()
            .expect("client_id should exist")
            .to_string();
        let client_secret = body["clientSecret"]
            .as_str()
            .expect("client_secret should exist")
            .to_string();
        (client_id, client_secret)
    }

    /// Create a Kratos identity via the public registration API and return `(identity_id, session_token)`.
    pub async fn create_kratos_identity(&self, email: &str) -> (String, String) {
        let public_url = &self.kratos_public_url;
        let client = &self.http;

        let flow: serde_json::Value = client
            .get(format!("{public_url}/self-service/registration/api"))
            .header("Accept", "application/json")
            .send()
            .await
            .expect("create registration flow request should succeed")
            .json()
            .await
            .expect("registration flow response should be json");

        let flow_id = flow["id"].as_str().expect("flow id should exist");
        let csrf_token = flow["ui"]["nodes"]
            .as_array()
            .and_then(|nodes| {
                nodes.iter().find_map(|n| {
                    if n["attributes"]["name"] == "csrf_token" {
                        n["attributes"]["value"].as_str()
                    } else {
                        None
                    }
                })
            })
            .unwrap_or("");

        let mut body = serde_json::json!({
            "method": "password",
            "password": "TestPass123!",
            "traits": { "email": email }
        });
        if !csrf_token.is_empty() {
            body["csrf_token"] = serde_json::json!(csrf_token);
        }

        let resp = client
            .post(format!("{public_url}/self-service/registration"))
            .query(&[("flow", flow_id)])
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("submit registration request should succeed");

        let status = resp.status();
        let text = resp
            .text()
            .await
            .expect("registration submit body should be text");
        assert!(
            status.is_success(),
            "registration submit failed: {status} {text}"
        );

        let result: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("registration submit should be json: {e}\n{text}"));

        let session_token = result["session_token"]
            .as_str()
            .expect("session_token should exist")
            .to_string();
        let identity_id = result["identity"]["id"]
            .as_str()
            .expect("identity id should exist")
            .to_string();

        (identity_id, session_token)
    }

    /// Create a SAML 2.0 provider record and return its id.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_saml_provider(
        &self,
        name: &str,
        idp_entity_id: &str,
        idp_sso_url: &str,
        idp_certificate_pem: Option<&str>,
        sp_entity_id: &str,
        acs_url: &str,
        name_id_format: Option<&str>,
        schema_id: &str,
        authn_requests_signed: bool,
    ) -> String {
        let store = PgSamlProviderStore::new(self.pool.clone());
        store
            .create(
                &self.system_tenant_ulid,
                name,
                idp_entity_id,
                idp_sso_url,
                idp_certificate_pem,
                sp_entity_id,
                acs_url,
                name_id_format,
                schema_id,
                authn_requests_signed,
            )
            .await
            .expect("saml provider should be created")
            .id
    }

    /// Create a SAML 2.0 SP client record and return its id.
    pub async fn create_saml_sp_client(
        &self,
        entity_id: &str,
        acs_url: &str,
        certificate_pem: Option<&str>,
        authn_requests_signed: bool,
        name_id_format: Option<&str>,
    ) -> String {
        let store = PgSamlSpClientStore::new(self.pool.clone());
        store
            .create(
                &self.system_tenant_ulid,
                entity_id,
                acs_url,
                certificate_pem,
                authn_requests_signed,
                name_id_format,
            )
            .await
            .expect("saml sp client should be created")
            .id
    }

    /// Generate an RSA signing key and self-signed certificate, store it as the
    /// active SAML IdP key for the system tenant, and return `(key_id, private_key_pem, certificate_pem)`.
    pub async fn create_saml_idp_key(&self) -> (String, String, String) {
        use rsa::pkcs8::EncodePrivateKey;

        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
            .expect("rsa private key should generate");
        let private_key_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::default())
            .expect("private key should serialize")
            .to_string();
        let key_pair = rcgen::KeyPair::from_pem(&private_key_pem)
            .expect("rcgen should load the rsa private key");

        let params = rcgen::CertificateParams::new(vec!["saml-conformance".to_string()])
            .expect("certificate params should build");
        let cert = params
            .self_signed(&key_pair)
            .expect("self-signed certificate should generate");
        let certificate_pem = cert.pem();
        let key_id = ulid::Ulid::new().to_string();

        let store = PgSamlIdpKeyStore::with_encryption_key(self.pool.clone(), vec![0u8; 32]);
        store
            .create(
                &self.system_tenant_ulid,
                &key_id,
                &private_key_pem,
                &certificate_pem,
                true,
            )
            .await
            .expect("saml idp key should be created");

        (key_id, private_key_pem, certificate_pem)
    }

    /// Resolve the Ory Hydra client id for a gateway application. This is only
    /// used internally by conformance tests to drive the browser-oriented OIDC
    /// authorization flow against Hydra directly; the gateway's public API
    /// never exposes this value.
    pub async fn get_hydra_client_id(&self, app_id: &str) -> Result<String, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT ory_global_id FROM id_mappings WHERE backend = 'hydra' AND public_id = $1",
        )
        .bind(app_id)
        .fetch_one(&self.pool)
        .await
    }
}

async fn fetch_bootstrap_token(
    client: &reqwest::Client,
    base_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let resp = client
        .post(format!("{base_url}/oauth2/token"))
        .basic_auth(client_id, Some(client_secret))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", "tenant:admin application:admin"),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!("token request failed: {}", resp.status()).into());
    }

    let body: serde_json::Value = resp.json().await?;
    let token = body["access_token"]
        .as_str()
        .ok_or("missing access_token in token response")?;
    Ok(token.to_string())
}

async fn wait_for_ok(
    client: &reqwest::Client,
    url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match client.get(url).send().await {
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
