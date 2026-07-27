#![cfg(feature = "keto")]

//! Integration tests for the universal login HTTP callbacks.
//!
//! These tests start the full gateway stack (Postgres, Hydra, Kratos, Keto) and
//! exercise end-to-end OIDC/OAuth2/SAML callback flows, including identity
//! provisioning and browser session creation.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
use gamlastan::core::assertion::name_id::NameId;
use gamlastan::core::constants;
use gamlastan::crypto::SamlSigner;
use gamlastan::crypto::keys::build_idp_keys_manager;
use gamlastan::profiles::sso::idp::create_response;
use gamlastan::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
use gamlastan::xml::SamlSerialize;
use serde_json::json;
use sso_gateway::{
    app::build_app_with_upstream,
    config::Config,
    db::{IdentitySchemaRepo, SamlProviderRepo, TenantConnectionRepo, create_pool},
    upstream_oauth::{UpstreamOAuthClient, UpstreamTokenResponse},
};
use sso_ory_client::HydraClient;
use sunbeam_g2v::server::axum::bind_random_port;
use testcontainers::ContainerAsync;
use testcontainers::GenericImage;

mod support;

/// Stub upstream OAuth2 client that returns a fixed token and userinfo.
///
/// Allows callback integration tests to exercise the full gateway stack without
/// relying on a real HTTPS upstream IdP.
#[derive(Clone, Default)]
struct StubUpstreamOAuthClient {
    email: String,
}

#[async_trait]
impl UpstreamOAuthClient for StubUpstreamOAuthClient {
    async fn exchange_code(
        &self,
        _config: &serde_json::Value,
        _code: &str,
        _redirect_uri: &str,
        _code_verifier: Option<&str>,
    ) -> Result<UpstreamTokenResponse, sso_gateway::upstream_oauth::UpstreamOAuthError> {
        Ok(UpstreamTokenResponse {
            access_token: "stub-access-token".into(),
            token_type: "Bearer".into(),
            id_token: None,
            raw: json!({"access_token": "stub-access-token"}),
        })
    }

    async fn fetch_userinfo(
        &self,
        _config: &serde_json::Value,
        _token_response: &UpstreamTokenResponse,
    ) -> Result<serde_json::Value, sso_gateway::upstream_oauth::UpstreamOAuthError> {
        Ok(json!({"email": self.email, "email_verified": true}))
    }
}

/// A running gateway instance configured for universal login callback tests.
struct CallbackHarness {
    base_url: String,
    admin_token: String,
    #[allow(dead_code)]
    system_tenant_ulid: String,
    http: reqwest::Client,
    hydra_admin_url: String,
    hydra_public_url: String,
    #[allow(dead_code)]
    kratos_public_url: String,
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

impl CallbackHarness {
    async fn start() -> Self {
        Self::start_with_upstream(None).await
    }

    async fn start_with_upstream(upstream_oauth: Option<Arc<dyn UpstreamOAuthClient>>) -> Self {
        let (_pg, database_url) = support::start_postgres()
            .await
            .expect("postgres should start");
        let (_kratos, kratos_admin_url, kratos_public_url) =
            support::start_kratos().await.expect("kratos should start");
        let (_keto, keto_read_url, keto_write_url) =
            support::start_keto().await.expect("keto should start");

        let pool = create_pool(&database_url, false)
            .await
            .expect("database pool should be created");

        let system_tenant_ulid = ulid::Ulid::new().to_string();

        // Bind the gateway port before starting Hydra so Hydra issues tokens
        // with the gateway's public URL as the issuer.
        let (listener, addr) = bind_random_port("127.0.0.1")
            .await
            .expect("random port should bind");
        let public_base_url = format!("http://{addr}");

        let (_hydra, hydra_admin_url, hydra_public_url) =
            support::start_hydra_with_issuer(&public_base_url)
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
            force_email_claim_client_ids: Vec::new(),
            system_bootstrap_client_id: Some("integration-test-admin-client".to_string()),
            system_bootstrap_client_secret: Some("integration-test-admin-secret".to_string()),
            state_cookie_secret: "callback-test-secret-key-at-least-32-bytes-long".into(),
            cookie_secure: true,
            cookie_samesite: "Lax".to_string(),
            saml_idp_key_encryption_key: None,
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

        let app = build_app_with_upstream(&config, pool.clone(), upstream_oauth)
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
        .expect("gateway should be ready");

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
            admin_token,
            system_tenant_ulid,
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

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }

    /// Register a default identity schema in the system tenant.
    ///
    /// The system tenant is the one resolved from the bootstrap admin token, so
    /// all universal-login resources must live there for these callback tests.
    async fn ensure_system_schema(&self) -> String {
        let schemas = IdentitySchemaRepo::new(self.pool.clone());
        schemas
            .create(
                &self.system_tenant_ulid,
                "default",
                json!({
                    "$id": "https://schemas.ory.sh/presets/kratos/quickstart/email-password/identity.schema.json",
                    "$schema": "http://json-schema.org/draft-07/schema#",
                    "title": "Person",
                    "type": "object",
                    "properties": {
                        "traits": {
                            "type": "object",
                            "properties": {
                                "email": {
                                    "type": "string",
                                    "format": "email",
                                    "title": "E-Mail",
                                    "ory.sh/kratos": {
                                        "credentials": { "password": { "identifier": true } },
                                        "recovery": { "via": "email" },
                                        "verification": { "via": "email" }
                                    }
                                },
                                "name": { "type": "object" },
                                "tenant_id": { "type": "string" }
                            },
                            "required": ["email"],
                            "additionalProperties": false
                        }
                    }
                }),
                true,
            )
            .await
            .expect("schema should be registered");

        self.system_tenant_ulid.clone()
    }

    /// Mark a tenant domain as verified so upstream connections can use it.
    async fn ensure_verified_domain(&self, domain: &str) {
        let domain_id = ulid::Ulid::new().to_string();
        sqlx::query(
            "INSERT INTO tenant_domains \
             (id, tenant_id, domain, verification_token, is_verified, verified_at) \
             VALUES ($1, $2, $3, $4, TRUE, NOW())",
        )
        .bind(&domain_id)
        .bind(&self.system_tenant_ulid)
        .bind(domain)
        .bind("verification-token")
        .execute(&self.pool)
        .await
        .expect("domain should be verified");
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
            ("scope", "tenant:admin"),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("token request failed: {body}").into());
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

fn extract_query_param(url: &str, key: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find_map(|(k, v)| if k == key { Some(v.into_owned()) } else { None })
}

/// Resolve Hydra's localhost issuer URLs to the actual container address.
fn resolve_hydra_url(url: &str, gateway_base_url: &str, hydra_public_url: &str) -> String {
    let url = url.replacen("http://localhost:4444", hydra_public_url, 1);
    let url = url.replacen(gateway_base_url, hydra_public_url, 1);
    url.replacen("https://idp.example.com", hydra_public_url, 1)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oauth2_callback_redirects_with_session_cookie() {
    let upstream_email = "alice@acme.com".to_string();
    let harness = CallbackHarness::start_with_upstream(Some(Arc::new(StubUpstreamOAuthClient {
        email: upstream_email.clone(),
    })))
    .await;
    let tenant_id = harness.ensure_system_schema().await;
    harness.ensure_verified_domain("acme.com").await;

    // Create an upstream OAuth2 client directly in Hydra.
    let upstream_client_id = "upstream-oauth2-client";
    let upstream_client_secret = "upstream-oauth2-secret";
    let redirect_uri = format!("{}/callbacks/oauth2", harness.base_url);

    let hydra_client = HydraClient::new(&harness.hydra_admin_url, &harness.hydra_public_url)
        .expect("hydra client should build");
    hydra_client
        .create_oauth2_client(json!({
            "client_id": upstream_client_id,
            "client_secret": upstream_client_secret,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid profile email",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "client_secret_post"
        }))
        .await
        .expect("upstream client should be created");

    // Use a public-looking HTTPS URL for the upstream IdP; the test harness
    // maps it back to the local Hydra container for the authorize redirect, and
    // the stub upstream client handles token exchange and userinfo.
    let upstream_base = "https://idp.example.com";
    let connections = TenantConnectionRepo::new(harness.pool.clone());
    let connection = connections
        .create(
            &tenant_id,
            sso_gateway::db::ConnectionType::OAuth2,
            "acme.com",
            json!({
                "authorization_url": format!("{upstream_base}/oauth2/auth"),
                "token_url": format!("{upstream_base}/oauth2/token"),
                "userinfo_url": format!("{upstream_base}/userinfo"),
                "client_id": upstream_client_id,
                "client_secret": upstream_client_secret,
                "redirect_uri": redirect_uri,
                "scopes": ["openid", "profile", "email"]
            }),
        )
        .await
        .expect("connection should be created");

    // Initiate the OAuth2 login to obtain a state-bound authorization URL.
    let initiate_resp = harness
        .http
        .post(format!(
            "{}/iam.v1.FederationService/InitiateOAuth2Login",
            harness.base_url
        ))
        .header("authorization", format!("Bearer {}", harness.admin_token))
        .header("content-type", "application/json")
        .json(&json!({
            "connectionId": connection.id,
            "returnTo": "https://app.example.com/dashboard"
        }))
        .send()
        .await
        .expect("initiate request should succeed");
    let initiate_status = initiate_resp.status();
    let initiate_body = initiate_resp
        .text()
        .await
        .expect("initiate response should be text");
    assert!(
        initiate_status.is_success(),
        "initiate oauth2 login failed: {initiate_status} {initiate_body}"
    );
    let initiate: serde_json::Value =
        serde_json::from_str(&initiate_body).expect("initiate response should be json");

    let auth_url = initiate["authorizationUrl"]
        .as_str()
        .expect("authorizationUrl should exist");
    let auth_url = resolve_hydra_url(auth_url, &harness.base_url, &harness.hydra_public_url);

    // Follow the authorization URL through Hydra login/consent without
    // following the final redirect back to the gateway callback.
    let no_redirect = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .expect("no-redirect client should build");

    let auth_resp = no_redirect
        .get(auth_url)
        .send()
        .await
        .expect("authorize request should complete");
    assert!(
        auth_resp.status().is_redirection(),
        "authorize should redirect to login: {:?}",
        auth_resp.status()
    );
    let login_location = auth_resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("login location should exist");
    let login_location =
        resolve_hydra_url(login_location, &harness.base_url, &harness.hydra_public_url);
    let login_challenge = extract_query_param(&login_location, "login_challenge")
        .expect("login_challenge should be present");

    let login_accept: serde_json::Value = no_redirect
        .put(format!(
            "{}/admin/oauth2/auth/requests/login/accept",
            harness.hydra_admin_url
        ))
        .query(&[("login_challenge", &login_challenge)])
        .json(&json!({
            "subject": "alice@acme.com",
            "remember": false,
        }))
        .send()
        .await
        .expect("login accept should succeed")
        .json()
        .await
        .expect("login accept should be json");
    let after_login = login_accept["redirect_to"]
        .as_str()
        .expect("redirect_to should exist");

    let after_login = resolve_hydra_url(after_login, &harness.base_url, &harness.hydra_public_url);
    let consent_resp = no_redirect
        .get(&after_login)
        .send()
        .await
        .expect("login redirect should complete");
    assert!(
        consent_resp.status().is_redirection(),
        "after login should redirect to consent: {:?}",
        consent_resp.status()
    );
    let consent_location = consent_resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("consent location should exist");
    let consent_location = resolve_hydra_url(
        consent_location,
        &harness.base_url,
        &harness.hydra_public_url,
    );
    let consent_challenge = extract_query_param(&consent_location, "consent_challenge")
        .or_else(|| extract_query_param(&consent_location, "consent_verifier"))
        .expect("consent_challenge or verifier should be present");

    let consent_accept: serde_json::Value = no_redirect
        .put(format!(
            "{}/admin/oauth2/auth/requests/consent/accept",
            harness.hydra_admin_url
        ))
        .query(&[("consent_challenge", &consent_challenge)])
        .json(&json!({
            "grant_scope": ["openid", "profile", "email"],
            "remember": false,
            "session": {
                "access_token": { "email": "alice@acme.com" },
                "id_token": { "email": "alice@acme.com" }
            }
        }))
        .send()
        .await
        .expect("consent accept should succeed")
        .json()
        .await
        .expect("consent accept should be json");
    let redirect_to = consent_accept["redirect_to"]
        .as_str()
        .expect("redirect_to should exist");

    let redirect_to = resolve_hydra_url(redirect_to, &harness.base_url, &harness.hydra_public_url);
    let final_resp = no_redirect
        .get(&redirect_to)
        .send()
        .await
        .expect("consent verifier redirect should complete");
    assert!(
        final_resp.status().is_redirection(),
        "consent accept should redirect to callback: {:?}",
        final_resp.status()
    );
    let final_location = final_resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .expect("final location should exist");

    let code = extract_query_param(final_location, "code").expect("code should exist");
    let state = extract_query_param(final_location, "state").expect("state should exist");

    // Invoke the public OAuth2 callback on the gateway.  Do not follow the
    // redirect so we can inspect the 302 and the session cookie.
    let callback_http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .expect("callback http client should build");
    let callback_resp = callback_http
        .get(format!("{}/callbacks/oauth2", harness.base_url))
        .query(&[("code", code), ("state", state)])
        .send()
        .await
        .expect("callback request should complete");

    assert!(
        callback_resp.status().is_redirection(),
        "callback should redirect to return_to: {:?} {:?}",
        callback_resp.status(),
        callback_resp.text().await.unwrap_or_default()
    );
    assert_eq!(
        callback_resp
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok()),
        Some("https://app.example.com/dashboard")
    );
    let set_cookie = callback_resp
        .headers()
        .get("set-cookie")
        .expect("session cookie should be set");
    assert!(
        set_cookie
            .to_str()
            .unwrap()
            .starts_with("__Host-sso_session="),
        "cookie should be the sso_session"
    );

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saml_acs_callback_redirects_with_session_cookie() {
    let harness = CallbackHarness::start().await;
    let tenant_id = harness.ensure_system_schema().await;
    harness.ensure_verified_domain("acme.com").await;

    // Load a SAML signing key/certificate pair so the provider can verify the
    // IdP response signature.
    let saml_key_pem = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-test-key.pem"
    ))
    .expect("read saml test key");
    let saml_cert_pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/saml-test-cert.pem"
    ))
    .expect("read saml test cert");
    let key_manager = build_idp_keys_manager(&saml_key_pem).expect("load saml test key");
    let signer = SamlSigner::new(key_manager);

    // Register a SAML provider with the IdP certificate so signed assertions are
    // accepted.
    let providers = SamlProviderRepo::new(harness.pool.clone());
    let provider = providers
        .create(
            &tenant_id,
            "test-idp",
            "https://idp.example.com",
            "https://idp.example.com/sso",
            Some(&saml_cert_pem),
            "https://sp.example.com",
            "https://sp.example.com/acs",
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
            "default",
            false,
        )
        .await
        .expect("provider should be created");

    // Initiate SAML login to obtain a pending request id.
    let initiate_resp = harness
        .http
        .post(format!(
            "{}/iam.v1.FederationService/InitiateSamlLogin",
            harness.base_url
        ))
        .header("authorization", format!("Bearer {}", harness.admin_token))
        .header("content-type", "application/json")
        .json(&json!({
            "providerId": provider.id,
            "relayState": "https://app.example.com/dashboard"
        }))
        .send()
        .await
        .expect("initiate saml login request should succeed");
    let initiate_status = initiate_resp.status();
    let initiate_body = initiate_resp
        .text()
        .await
        .expect("initiate saml response should be text");
    assert!(
        initiate_status.is_success(),
        "initiate saml login failed: {initiate_status} {initiate_body}"
    );
    let initiate: serde_json::Value =
        serde_json::from_str(&initiate_body).expect("initiate saml response should be json");

    let request_id = initiate["requestId"]
        .as_str()
        .expect("requestId should exist");

    // Build a signed SAML response as if it came back from the IdP.
    let saml_xml = build_saml_response(
        request_id,
        &provider.sp_entity_id,
        &provider.acs_url,
        "alice@acme.com",
        Some(&signer),
    );
    let encoded_assertion = base64::engine::general_purpose::STANDARD.encode(saml_xml.as_bytes());

    let saml_callback_http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .expect("saml callback http client should build");
    let callback_resp = saml_callback_http
        .post(format!("{}/saml/acs", harness.base_url))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "SAMLResponse={}&RelayState={}",
            urlencoding::encode(&encoded_assertion),
            urlencoding::encode("https://app.example.com/dashboard")
        ))
        .send()
        .await
        .expect("saml acs request should complete");

    assert!(
        callback_resp.status().is_redirection(),
        "saml acs should redirect to return_to: {:?} {:?}",
        callback_resp.status(),
        callback_resp.text().await.unwrap_or_default()
    );
    assert_eq!(
        callback_resp
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok()),
        Some("https://app.example.com/dashboard")
    );
    let set_cookie = callback_resp
        .headers()
        .get("set-cookie")
        .expect("session cookie should be set");
    assert!(
        set_cookie
            .to_str()
            .unwrap()
            .starts_with("__Host-sso_session="),
        "cookie should be the sso_session"
    );

    harness.shutdown().await;
}

fn build_saml_response(
    request_id: &str,
    sp_entity_id: &str,
    acs_url: &str,
    email: &str,
    signer: Option<&SamlSigner>,
) -> String {
    use chrono::Utc;

    let options = ResponseOptions {
        idp_entity_id: "https://idp.example.com".to_string(),
        in_response_to: Some(request_id.to_string()),
        sp_entity_id: sp_entity_id.to_string(),
        acs_url: acs_url.to_string(),
        assertion_lifetime_seconds: 300,
        session_index: Some("_session_1".to_string()),
        session_not_on_or_after: None,
        authn_context_class_ref: Some(constants::AUTHN_CONTEXT_PASSWORD.to_string()),
        client_address: None,
        attributes: vec![Attribute {
            name: "email".to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![AttributeValue::String(email.to_string())],
        }],
    };
    let name_id = NameId {
        value: email.to_string(),
        format: Some(constants::NAMEID_EMAIL.to_string()),
        name_qualifier: None,
        sp_name_qualifier: None,
        sp_provided_id: None,
    };
    let response = create_response(&options, &name_id, ResponseTimes::at(Utc::now()));
    let response_id = response.base.id.clone();
    let mut xml = response.to_xml_string().expect("serialize response");

    if let Some(signer) = signer {
        let template = response_signature_template(&response_id);
        let status_pos = xml
            .find("<samlp:Status")
            .expect("status element in serialized response");
        xml.insert_str(status_pos, &template);
        xml = signer.sign_enveloped(&xml).expect("sign saml response");
    }

    xml
}

fn response_signature_template(response_id: &str) -> String {
    format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#{response_id}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue></ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue></ds:SignatureValue>
            <ds:KeyInfo><ds:X509Data/></ds:KeyInfo>
        </ds:Signature>"##
    )
}
