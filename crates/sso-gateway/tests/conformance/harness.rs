#![allow(dead_code)]

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
}

/// Result of driving an authorization-code, implicit, or hybrid flow through the
/// gateway.
pub struct AuthorizationFlowResult {
    pub ory_client_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub code: String,
    /// Token endpoint response (authorization-code, refresh-token, client-creds,
    /// or implicit fragment parsed as JSON).
    pub token: serde_json::Value,
    /// ID token returned directly from a hybrid flow response fragment, if any.
    pub id_token: Option<String>,
}

impl Gateway {
    /// Create an OAuth2/OIDC application and return the created resource as JSON.
    pub async fn create_application(
        &self,
        name: &str,
        redirect_uris: &[&str],
        grant_types: &[&str],
        response_types: &[&str],
        scopes: &[&str],
    ) -> serde_json::Value {
        self.create_application_with_auth(
            name,
            redirect_uris,
            grant_types,
            response_types,
            scopes,
            "client_secret_post",
        )
        .await
    }

    /// Create an OAuth2/OIDC application with an explicit token endpoint auth
    /// method and return the created resource as JSON.
    pub async fn create_application_with_auth(
        &self,
        name: &str,
        redirect_uris: &[&str],
        grant_types: &[&str],
        response_types: &[&str],
        scopes: &[&str],
        token_endpoint_auth_method: &str,
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
                "tokenEndpointAuthMethod": token_endpoint_auth_method
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

    /// Perform a full authorization-code or implicit flow through the gateway's
    /// public `/oauth2/auth` endpoint.
    ///
    /// Login and consent are accepted directly against Hydra's admin API so the
    /// test can focus on the gateway's public OAuth2 surface. Any Hydra-issued
    /// redirect URLs are rewritten back onto the gateway host before following.
    #[allow(clippy::too_many_arguments)]
    pub async fn authorization_code_flow_through_gateway(
        &self,
        subject: &str,
        redirect_uri: &str,
        grant_types: &[&str],
        response_types: &[&str],
        scopes: &[&str],
        use_pkce: bool,
        nonce: Option<&str>,
    ) -> AuthorizationFlowResult {
        // Hydra matches the requested response_type as a space-separated string
        // against the client's registered response_types list, so register the
        // exact combination (e.g. "code id_token") as a single element.
        let response_type = response_types.join(" ");
        let app = self
            .create_application(
                "oauth2-auth-code-gateway",
                &[redirect_uri],
                grant_types,
                &[response_type.as_str()],
                scopes,
            )
            .await;
        let app_id = app["id"].as_str().expect("app id");
        let (client_id, client_secret) = self.rotate_secret(app_id).await;
        let ory_client_id = self
            .get_hydra_client_id(app_id)
            .await
            .expect("ory client id should be resolvable");

        let no_redirect = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("no-redirect client should build");

        let (code_verifier, code_challenge) = if use_pkce {
            let verifier = generate_code_verifier();
            let challenge = generate_code_challenge(&verifier);
            (Some(verifier), Some(challenge))
        } else {
            (None, None)
        };

        // 1. Initiate the authorization request through the gateway.
        let scope = scopes.join(" ");
        let state = "conformance-state".to_string();
        let mut auth_query: Vec<(&str, String)> = vec![
            ("response_type", response_type),
            ("client_id", client_id.clone()),
            ("redirect_uri", redirect_uri.to_string()),
            ("scope", scope),
            ("state", state),
        ];
        if let Some(challenge) = code_challenge.clone() {
            auth_query.push(("code_challenge", challenge));
            auth_query.push(("code_challenge_method", "S256".to_string()));
        }
        if let Some(nonce) = nonce {
            auth_query.push(("nonce", nonce.to_string()));
        }

        let auth_resp = no_redirect
            .get(format!("{}/oauth2/auth", self.base_url))
            .query(&auth_query)
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
            .expect("login location header should exist");
        let login_location = resolve_to_gateway_url(login_location, &self.base_url, &self.hydra_public_url);
        assert!(
            login_location.contains("login_challenge="),
            "authorize did not redirect to login; location: {login_location}"
        );
        let login_challenge = extract_query_param(&login_location, "login_challenge")
            .expect("login_challenge should be present");

        // 2. Accept the login request.
        let login_accept: serde_json::Value = no_redirect
            .put(format!(
                "{}/admin/oauth2/auth/requests/login/accept",
                self.hydra_admin_url
            ))
            .query(&[("login_challenge", &login_challenge)])
            .json(&serde_json::json!({
                "subject": subject,
                "remember": false,
            }))
            .send()
            .await
            .expect("login accept request should succeed")
            .json()
            .await
            .expect("login accept should be json");
        let after_login = login_accept["redirect_to"]
            .as_str()
            .expect("login accept should return redirect_to");

        // 3. Follow the login verifier redirect through the gateway.
        let after_login = resolve_to_gateway_url(after_login, &self.base_url, &self.hydra_public_url);
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
            .expect("consent location header should exist");
        let consent_location = resolve_to_gateway_url(consent_location, &self.base_url, &self.hydra_public_url);
        let consent_challenge = extract_query_param(&consent_location, "consent_challenge")
            .or_else(|| extract_query_param(&consent_location, "consent_verifier"))
            .expect("consent_challenge or consent_verifier should be present");

        // 4. Accept the consent request.
        let consent_accept: serde_json::Value = no_redirect
            .put(format!(
                "{}/admin/oauth2/auth/requests/consent/accept",
                self.hydra_admin_url
            ))
            .query(&[("consent_challenge", &consent_challenge)])
            .json(&serde_json::json!({
                "grant_scope": scopes,
                "remember": false,
            }))
            .send()
            .await
            .expect("consent accept request should succeed")
            .json()
            .await
            .expect("consent accept should be json");
        let redirect_to = consent_accept["redirect_to"]
            .as_str()
            .expect("consent accept should return redirect_to");

        // 5. Follow the consent verifier redirect through the gateway.
        let redirect_to = resolve_to_gateway_url(redirect_to, &self.base_url, &self.hydra_public_url);
        let final_resp = no_redirect
            .get(&redirect_to)
            .send()
            .await
            .expect("consent verifier redirect should complete");
        assert!(
            final_resp.status().is_redirection(),
            "consent accept should redirect to client redirect_uri: {:?}",
            final_resp.status()
        );
        let final_location = final_resp
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .expect("final location header should exist");

        // 6. Extract the authorization result from the final redirect URI.
        let redirect_url = url::Url::parse(final_location)
            .unwrap_or_else(|_| panic!("final redirect should be a valid URL: {final_location}"));
        assert_eq!(
            redirect_url.origin().unicode_serialization(),
            url::Url::parse(redirect_uri).unwrap().origin().unicode_serialization(),
            "final redirect must target the requested redirect_uri"
        );
        // 6. Extract the authorization result from the final redirect URI.
        //    Pure implicit flows return parameters in the fragment; hybrid flows
        //    may return both query parameters (code) and fragment parameters
        //    (id_token, access_token).
        let fragment_params = redirect_url
            .fragment()
            .map(fragment_to_map)
            .unwrap_or_default();
        let query_params: std::collections::HashMap<String, String> = redirect_url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            query_params.get("state").map(String::as_str).or(fragment_params.get("state").map(String::as_str)),
            Some("conformance-state"),
            "authorization response must return the requested state"
        );

        // Pure implicit flow: everything lives in the fragment.
        if response_types.contains(&"token") && !response_types.contains(&"code") {
            assert!(
                fragment_params.contains_key("access_token"),
                "implicit flow fragment must contain access_token: {fragment_params:?}"
            );
            let id_token = fragment_params.get("id_token").cloned();
            let token = serde_json::Value::Object(
                fragment_params
                    .into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect(),
            );
            return AuthorizationFlowResult {
                ory_client_id,
                client_id,
                client_secret,
                code: String::new(),
                token,
                id_token,
            };
        }

        let code = match query_params.get("code").cloned().or_else(|| {
            // Some OPs (including Hydra for some hybrid configurations) return
            // the authorization code in the fragment rather than the query.
            fragment_params.get("code").cloned()
        }) {
            Some(code) => code,
            None => panic!(
                "redirect should contain code; location={final_location} query={query_params:?} fragment={fragment_params:?}"
            ),
        };
        let hybrid_id_token = fragment_params.get("id_token").cloned();

        // 7. Exchange the code at the gateway token endpoint using the public
        //    client id to verify the gateway maps it back to the Ory client.
        let mut token_form: Vec<(&str, String)> = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.clone()),
            ("redirect_uri", redirect_uri.to_string()),
            ("client_id", client_id.clone()),
            ("client_secret", client_secret.clone()),
        ];
        if let Some(verifier) = code_verifier {
            token_form.push(("code_verifier", verifier));
        }

        let token: serde_json::Value = self
            .http
            .post(format!("{}/oauth2/token", self.base_url))
            .form(&token_form)
            .send()
            .await
            .expect("token exchange should succeed")
            .json()
            .await
            .expect("token response should be json");

        AuthorizationFlowResult {
            ory_client_id,
            client_id,
            client_secret,
            code,
            token,
            id_token: hybrid_id_token,
        }
    }

    /// Exchange a refresh token at the gateway token endpoint.
    pub async fn refresh_token_flow(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
    ) -> serde_json::Value {
        self.http
            .post(format!("{}/oauth2/token", self.base_url))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("scope", "openid offline_access"),
            ])
            .send()
            .await
            .expect("refresh token request should succeed")
            .json()
            .await
            .expect("refresh token response should be json")
    }

    /// Complete a full OAuth2 device-code flow through the gateway and return
    /// the token response. Login and consent are accepted directly against
    /// Hydra's admin API; the device verification leg exercises the gateway's
    /// `/oauth2/device/verify` proxy and the Connect-RPC device service.
    pub async fn device_code_flow(&self, subject: &str) -> serde_json::Value {
        let scopes = vec!["openid", "profile"];
        let app = self
            .create_application_with_auth(
                "oauth2-device-gateway",
                &[REDIRECT_URI],
                &["urn:ietf:params:oauth:grant-type:device_code"],
                &["token"],
                &scopes,
                "none",
            )
            .await;
        let app_id = app["id"].as_str().expect("app id");
        let client_id = app_id.to_string();

        // 1. Initiate the device flow.
        let auth_resp = self
            .http
            .post(format!(
                "{}/iam.v1.OAuth2DeviceService/AuthorizeDevice",
                self.base_url
            ))
            .header("authorization", format!("Bearer {}", self.admin_token))
            .header("content-type", "application/json")
            .json(&serde_json::json!({
                "clientId": client_id,
                "scope": scopes,
            }))
            .send()
            .await
            .expect("authorize_device request should complete");
        let auth_status = auth_resp.status();
        let auth_body = auth_resp
            .text()
            .await
            .expect("authorize_device response should have a body");
        assert!(
            auth_status.is_success(),
            "authorize_device failed: {} - {}",
            auth_status,
            auth_body
        );
        let auth: serde_json::Value = serde_json::from_str(&auth_body)
            .expect("authorize_device response should be json");
        let device_code = auth["deviceCode"]
            .as_str()
            .expect("deviceCode should exist")
            .to_string();
        let user_code = auth["userCode"]
            .as_str()
            .expect("userCode should exist")
            .to_string();

        // 2. Resolve the user code to a gateway challenge and capture Hydra's
        //    device CSRF cookie.
        let verify_resp = self
            .http
            .post(format!(
                "{}/iam.v1.OAuth2DeviceService/GetDeviceVerification",
                self.base_url
            ))
            .header("authorization", format!("Bearer {}", self.admin_token))
            .header("content-type", "application/json")
            .json(&serde_json::json!({ "userCode": user_code }))
            .send()
            .await
            .expect("get_device_verification request should succeed");
        let set_cookies: Vec<String> = verify_resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(String::from))
            .collect();
        let cookie_header = set_cookies
            .iter()
            .filter_map(|c| c.split(';').next().map(str::to_owned))
            .collect::<Vec<_>>()
            .join("; ");
        let verification: serde_json::Value = verify_resp
            .json()
            .await
            .expect("get_device_verification response should be json");
        let challenge = verification["challenge"]
            .as_str()
            .expect("challenge should exist")
            .to_string();

        // 3. Approve the device verification.
        let accepted: serde_json::Value = self
            .http
            .post(format!(
                "{}/iam.v1.OAuth2DeviceService/AcceptDeviceVerification",
                self.base_url
            ))
            .header("authorization", format!("Bearer {}", self.admin_token))
            .header("content-type", "application/json")
            .json(&serde_json::json!({
                "challenge": challenge,
                "userCode": user_code,
            }))
            .send()
            .await
            .expect("accept_device_verification request should succeed")
            .json()
            .await
            .expect("accept_device_verification response should be json");
        let redirect_to = accepted["redirectTo"]
            .as_str()
            .expect("redirectTo should exist");

        // 4. Follow the verifier redirect through the gateway proxy to obtain the
        //    login challenge.
        let no_redirect = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("no-redirect client should build");
        let login_resp = no_redirect
            .get(redirect_to)
            .header("cookie", &cookie_header)
            .send()
            .await
            .expect("device verify leg should complete");
        assert!(
            login_resp.status().is_redirection(),
            "device verify leg should redirect to login: {:?}",
            login_resp.status()
        );
        let login_location = login_resp
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .expect("login location should exist");
        let login_location = resolve_to_gateway_url(login_location, &self.base_url, &self.hydra_public_url);
        assert!(
            login_location.contains("login_challenge="),
            "authorize did not redirect to login; location: {login_location}"
        );
        let login_challenge = extract_query_param(&login_location, "login_challenge")
            .expect("login_challenge should be present");

        // 5. Accept the login request.
        let login_accept: serde_json::Value = no_redirect
            .put(format!(
                "{}/admin/oauth2/auth/requests/login/accept",
                self.hydra_admin_url
            ))
            .query(&[("login_challenge", &login_challenge)])
            .json(&serde_json::json!({
                "subject": subject,
                "remember": false,
            }))
            .send()
            .await
            .expect("login accept request should succeed")
            .json()
            .await
            .expect("login accept should be json");
        let after_login = login_accept["redirect_to"]
            .as_str()
            .expect("login accept should return redirect_to");

        // 6. Follow the login verifier redirect to obtain the consent challenge.
        let after_login = resolve_to_gateway_url(after_login, &self.base_url, &self.hydra_public_url);
        let consent_resp = no_redirect
            .get(&after_login)
            .send()
            .await
            .expect("login verifier redirect should complete");
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
        let consent_location = resolve_to_gateway_url(consent_location, &self.base_url, &self.hydra_public_url);
        let consent_challenge = extract_query_param(&consent_location, "consent_challenge")
            .or_else(|| extract_query_param(&consent_location, "consent_verifier"))
            .expect("consent_challenge or consent_verifier should be present");

        // 7. Accept the consent request.
        let consent_accept: serde_json::Value = no_redirect
            .put(format!(
                "{}/admin/oauth2/auth/requests/consent/accept",
                self.hydra_admin_url
            ))
            .query(&[("consent_challenge", &consent_challenge)])
            .json(&serde_json::json!({
                "grant_scope": scopes,
                "remember": false,
            }))
            .send()
            .await
            .expect("consent accept request should succeed")
            .json()
            .await
            .expect("consent accept should be json");
        let after_consent = consent_accept["redirect_to"]
            .as_str()
            .expect("consent accept should return redirect_to");

        // 8. Follow the consent verifier redirect; the device code is now bound.
        let after_consent = resolve_to_gateway_url(after_consent, &self.base_url, &self.hydra_public_url);
        let final_resp = no_redirect
            .get(&after_consent)
            .send()
            .await
            .expect("consent verifier redirect should complete");
        assert!(
            final_resp.status().is_redirection(),
            "consent accept should redirect after approval: {:?}",
            final_resp.status()
        );

        // 9. Poll the device code for tokens until approval propagates.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let token_resp = self
                .http
                .post(format!(
                    "{}/iam.v1.OAuth2DeviceService/GetDeviceToken",
                    self.base_url
                ))
                .header("authorization", format!("Bearer {}", self.admin_token))
                .header("content-type", "application/json")
                .json(&serde_json::json!({
                    "clientId": client_id,
                    "deviceCode": device_code,
                }))
                .send()
                .await
                .expect("get_device_token request should complete");
            let token_status = token_resp.status();
            let token_body = token_resp
                .text()
                .await
                .expect("get_device_token response should have a body");
            if token_status.is_success() {
                let token: serde_json::Value = serde_json::from_str(&token_body)
                    .expect("get_device_token response should be json");
                // Normalize the Connect-RPC camelCase response to standard
                // OAuth2 snake_case so callers can use the same assertions.
                return serde_json::json!({
                    "access_token": token.get("accessToken"),
                    "token_type": token.get("tokenType"),
                    "expires_in": token.get("expiresIn"),
                    "refresh_token": token.get("refreshToken"),
                    "id_token": token.get("idToken"),
                    "scope": token.get("scope"),
                });
            }
            if !token_body.to_ascii_lowercase().contains("pending") {
                panic!(
                    "get_device_token failed with non-pending error: {} - {}",
                    token_status, token_body
                );
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "get_device_token remained pending until deadline: {} - {}",
                    token_status, token_body
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

const REDIRECT_URI: &str = "https://127.0.0.1:9999/callback";

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

/// Rewrite a Hydra-issued URL onto the gateway host.
///
/// Hydra may still emit `http://localhost:4444` in some redirect chains even
/// when `URLS_SELF_ISSUER` points at the gateway, and verifier URLs use the
/// container address directly. Both are normalized to the gateway base URL so
/// tests follow the full public surface.
fn resolve_to_gateway_url(url: &str, gateway_base_url: &str, hydra_public_url: &str) -> String {
    let url = url.replacen("http://localhost:4444", gateway_base_url, 1);
    url.replacen(hydra_public_url, gateway_base_url, 1)
}

fn extract_query_param(url: &str, key: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find_map(|(k, v)| if k == key { Some(v.into_owned()) } else { None })
}

fn generate_code_verifier() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_code_challenge(verifier: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn fragment_to_map(fragment: &str) -> std::collections::HashMap<String, String> {
    url::form_urlencoded::parse(fragment.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}
