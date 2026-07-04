//! Browser callback handlers for upstream OIDC, OAuth2, and SAML logins.
//!
//! These endpoints are public (they receive IdP redirects) and are responsible
//! for validating the returned authorization code / assertion, provisioning or
//! linking a Kratos identity, creating a Kratos browser session, and redirecting
//! the browser back to the originating application.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Form, Query, State},
    http::{Response, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response as AxumResponse},
    routing::{get, post},
};
use serde_json::json;
use tracing::warn;

use crate::db::{DbError, LoginStateStore, SessionStore, TenantConnectionStore};
use crate::identity_provisioner::{IdentityProvisioner, ProvisionedIdentity};
use crate::jwks::JwksService;
use crate::session_token::SessionTokenSigner;
use crate::upstream_oauth::UpstreamOAuthClient;

const SESSION_COOKIE_NAME: &str = "__Host-sso_session";
const COOKIE_MAX_AGE_SECONDS: i64 = 86400;

/// Errors returned by callback handlers.
#[derive(Debug, thiserror::Error)]
pub enum CallbackError {
    #[error("invalid or expired state")]
    InvalidState,

    #[error("missing authorization code")]
    MissingCode,

    #[error("upstream token exchange failed")]
    TokenExchange,

    #[error("upstream userinfo failed")]
    Userinfo,

    #[error("identity provisioning failed")]
    Provisioning,

    #[error("session creation failed")]
    Session,

    #[error("configuration error: {0}")]
    Configuration(String),

    #[error("invalid return_to URL")]
    InvalidReturnTo,

    #[error("invalid id_token nonce")]
    InvalidNonce,

    #[error("invalid ID token")]
    InvalidIdToken,

    #[error("database error: {0}")]
    Database(#[from] DbError),

    #[error("service error: {0}")]
    Service(#[from] sunbeam_g2v::error::ServiceError),
}

impl IntoResponse for CallbackError {
    fn into_response(self) -> AxumResponse {
        warn!("callback error: {}", self);
        (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": self.to_string()})),
        )
            .into_response()
    }
}

/// SAML ACS operations abstracted so the handler can be tested with stubs.
#[async_trait]
pub trait SamlAcsService: Send + Sync + 'static {
    async fn process_saml_assertion_http(
        &self,
        encoded_assertion: &str,
        relay_state: &str,
    ) -> Result<ProvisionedIdentity, sunbeam_g2v::error::ServiceError>;
}

/// State shared by the OIDC/OAuth2/SAML callback handlers.
#[derive(Clone)]
pub struct CallbackState {
    pub(crate) login_state: Arc<dyn LoginStateStore>,
    pub(crate) connections: Arc<dyn TenantConnectionStore>,
    pub(crate) upstream_oauth: Arc<dyn UpstreamOAuthClient>,
    pub(crate) identity_provisioner: Arc<dyn IdentityProvisioner>,
    pub(crate) jwks_service: Arc<dyn JwksService>,
    pub(crate) saml: Option<Arc<dyn SamlAcsService>>,
    pub(crate) session_signer: SessionTokenSigner,
    pub(crate) session_store: Arc<dyn SessionStore>,
    pub(crate) allowed_return_to_hosts: Vec<String>,
    pub(crate) tenant_allowed_return_to_hosts: Option<Vec<String>>,
    pub(crate) public_base_url: String,
    pub(crate) cookie_secure: bool,
    pub(crate) cookie_samesite: String,
    pub(crate) session_ttl_seconds: u64,
    pub(crate) local_dev_mode: bool,
}

impl CallbackState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        login_state: Arc<dyn LoginStateStore>,
        connections: Arc<dyn TenantConnectionStore>,
        upstream_oauth: Arc<dyn UpstreamOAuthClient>,
        identity_provisioner: Arc<dyn IdentityProvisioner>,
        jwks_service: Arc<dyn JwksService>,
        session_signer: SessionTokenSigner,
        session_store: Arc<dyn SessionStore>,
        allowed_return_to_hosts: Vec<String>,
        public_base_url: String,
        cookie_secure: bool,
        cookie_samesite: String,
        session_ttl_seconds: u64,
    ) -> Self {
        Self {
            login_state,
            connections,
            upstream_oauth,
            identity_provisioner,
            jwks_service,
            saml: None,
            session_signer,
            session_store,
            allowed_return_to_hosts,
            tenant_allowed_return_to_hosts: None,
            public_base_url,
            cookie_secure,
            cookie_samesite,
            session_ttl_seconds,
            local_dev_mode: false,
        }
    }

    /// Attach a SAML ACS service; required for the `/saml/acs` route.
    pub fn with_saml(mut self, saml: Arc<dyn SamlAcsService>) -> Self {
        self.saml = Some(saml);
        self
    }
}

pub fn router(state: Arc<CallbackState>) -> Router {
    Router::new()
        .route("/callbacks/oidc", get(oidc_callback))
        .route("/callbacks/oauth2", get(oauth2_callback))
        .route("/saml/acs", post(saml_acs_callback))
        .with_state(state)
}

#[derive(Debug, serde::Deserialize)]
struct OauthCallbackQuery {
    code: String,
    state: String,
}

async fn oidc_callback(
    State(state): State<Arc<CallbackState>>,
    Query(params): Query<OauthCallbackQuery>,
) -> Result<Response<Body>, CallbackError> {
    handle_oauth_callback(state, params, "oidc").await
}

async fn oauth2_callback(
    State(state): State<Arc<CallbackState>>,
    Query(params): Query<OauthCallbackQuery>,
) -> Result<Response<Body>, CallbackError> {
    handle_oauth_callback(state, params, "oauth2").await
}

async fn handle_oauth_callback(
    state: Arc<CallbackState>,
    params: OauthCallbackQuery,
    connection_type: &str,
) -> Result<Response<Body>, CallbackError> {
    let login_state = state.login_state.get(&params.state).await?;
    if login_state.connection_type != connection_type {
        return Err(CallbackError::InvalidState);
    }

    state.login_state.delete(&params.state).await?;

    validate_return_to(
        &state.allowed_return_to_hosts,
        state.tenant_allowed_return_to_hosts.as_deref(),
        state.local_dev_mode,
        &login_state.return_to,
    )?;

    let connection = state
        .connections
        .get_by_id(&login_state.tenant_id, &login_state.connection_id)
        .await
        .map_err(|_| CallbackError::Configuration("connection not found".into()))?;

    let redirect_uri = format!(
        "{}/callbacks/{}",
        state.public_base_url.trim_end_matches('/'),
        connection_type
    );

    let token_response = state
        .upstream_oauth
        .exchange_code(
            &connection.config,
            &params.code,
            &redirect_uri,
            login_state.code_verifier.as_deref(),
        )
        .await
        .map_err(|e| {
            warn!("upstream token exchange failed: {e}");
            CallbackError::TokenExchange
        })?;

    // For OIDC flows, validate the ID token signature, issuer, audience, and
    // expiry. If a nonce was stored when the login was initiated, validate it
    // against the nonce claim as well.
    if connection_type == "oidc" {
        if let Some(id_token) = token_response.id_token.as_deref() {
            validate_id_token(
                id_token,
                &connection.config,
                login_state.nonce.as_deref(),
                &state.jwks_service,
            )
            .await?;
        } else if login_state.nonce.is_some() {
            return Err(CallbackError::InvalidIdToken);
        }
    }

    let userinfo = state
        .upstream_oauth
        .fetch_userinfo(&connection.config, &token_response)
        .await
        .map_err(|e| {
            warn!("upstream userinfo failed: {e}");
            CallbackError::Userinfo
        })?;

    let identity = provision_identity(&state, &login_state.tenant_id, &userinfo).await?;
    build_session_redirect(&state, &identity, connection_type, &login_state.return_to).await
}

async fn validate_id_token(
    id_token: &str,
    config: &serde_json::Value,
    expected_nonce: Option<&str>,
    jwks_service: &Arc<dyn JwksService>,
) -> Result<(), CallbackError> {
    let jwks_url = config["jwks_url"]
        .as_str()
        .ok_or_else(|| CallbackError::Configuration("missing jwks_url".into()))?;
    let issuer = config["issuer"]
        .as_str()
        .ok_or_else(|| CallbackError::Configuration("missing issuer".into()))?;
    let client_id = config["client_id"]
        .as_str()
        .ok_or_else(|| CallbackError::Configuration("missing client_id".into()))?;

    let header =
        jsonwebtoken::decode_header(id_token).map_err(|_| CallbackError::InvalidIdToken)?;

    let decoding_key = jwks_service
        .decoding_key_for_token(id_token, jwks_url)
        .await?;

    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);

    #[derive(serde::Deserialize)]
    struct IdTokenClaims {
        nonce: Option<String>,
        iat: Option<u64>,
    }

    let token_data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|_| CallbackError::InvalidIdToken)?;

    if let Some(iat) = token_data.claims.iat {
        let now = jsonwebtoken::get_current_timestamp();
        if iat > now + validation.leeway {
            return Err(CallbackError::InvalidIdToken);
        }
    }

    if let Some(expected) = expected_nonce {
        let actual = token_data
            .claims
            .nonce
            .as_deref()
            .ok_or(CallbackError::InvalidIdToken)?;
        if actual != expected {
            return Err(CallbackError::InvalidIdToken);
        }
    }

    Ok(())
}

async fn saml_acs_callback(
    State(state): State<Arc<CallbackState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response<Body>, CallbackError> {
    let saml = state
        .saml
        .as_ref()
        .ok_or_else(|| CallbackError::Configuration("SAML ACS not configured".into()))?;

    let encoded_assertion = form
        .get("SAMLResponse")
        .cloned()
        .ok_or(CallbackError::Configuration("missing SAMLResponse".into()))?;
    let relay_state = form.get("RelayState").cloned().unwrap_or_default();

    let identity = saml
        .process_saml_assertion_http(&encoded_assertion, &relay_state)
        .await
        .map_err(|e| {
            warn!("SAML ACS failed: {e}");
            CallbackError::Provisioning
        })?;

    let return_to = derive_saml_return_to(&state, &relay_state)?;
    build_session_redirect(&state, &identity, "saml", &return_to).await
}

async fn provision_identity(
    state: &CallbackState,
    tenant_id: &str,
    userinfo: &serde_json::Value,
) -> Result<ProvisionedIdentity, CallbackError> {
    let schema_id = userinfo["schema_id"].as_str().unwrap_or("default");

    state
        .identity_provisioner
        .provision(tenant_id, schema_id, userinfo)
        .await
        .map_err(|e| {
            warn!("identity provisioning failed: {e}");
            CallbackError::Provisioning
        })
}

async fn build_session_redirect(
    state: &CallbackState,
    identity: &ProvisionedIdentity,
    amr: &str,
    return_to: &str,
) -> Result<Response<Body>, CallbackError> {
    let (session_token, claims) = state
        .session_signer
        .issue(&identity.public_id, &identity.tenant_id, amr)
        .map_err(|e| {
            warn!("session token issuance failed: {e}");
            CallbackError::Session
        })?;

    let expires_at = time::OffsetDateTime::from_unix_timestamp(claims.exp).unwrap_or_else(|_| {
        time::OffsetDateTime::now_utc() + time::Duration::seconds(COOKIE_MAX_AGE_SECONDS)
    });
    state
        .session_store
        .create(&claims.sid, &claims.sub, &claims.tenant_id, amr, expires_at)
        .await?;

    let cookie = build_session_cookie(
        &session_token,
        state.cookie_secure,
        &state.cookie_samesite,
        state.session_ttl_seconds,
    );

    Response::builder()
        .status(StatusCode::FOUND)
        .header(axum::http::header::LOCATION, return_to)
        .header(SET_COOKIE, cookie)
        .body(Body::empty())
        .map_err(|e| CallbackError::Configuration(e.to_string()))
}

fn build_session_cookie(
    value: &str,
    secure: bool,
    same_site: &str,
    max_age_seconds: u64,
) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; Path=/; HttpOnly; SameSite={}; Max-Age={}{}",
        SESSION_COOKIE_NAME, value, same_site, max_age_seconds, secure_flag
    )
}

fn validate_return_to(
    allowed_hosts: &[String],
    tenant_allowed_hosts: Option<&[String]>,
    local_dev_mode: bool,
    return_to: &str,
) -> Result<(), CallbackError> {
    if allowed_hosts.is_empty() && tenant_allowed_hosts.map(|h| h.is_empty()).unwrap_or(true) {
        return Err(CallbackError::InvalidReturnTo);
    }

    let url = return_to
        .parse::<reqwest::Url>()
        .map_err(|_| CallbackError::InvalidReturnTo)?;
    let host = url.host_str().ok_or(CallbackError::InvalidReturnTo)?;

    if url.scheme() != "https" && !local_dev_mode {
        return Err(CallbackError::InvalidReturnTo);
    }

    if allowed_hosts.iter().any(|h| is_public_suffix(h))
        || tenant_allowed_hosts
            .iter()
            .flat_map(|h| h.iter())
            .any(|h| is_public_suffix(h))
    {
        return Err(CallbackError::InvalidReturnTo);
    }

    let matches = allowed_hosts
        .iter()
        .chain(tenant_allowed_hosts.iter().flat_map(|h| h.iter()))
        .any(|h| h == host);

    if matches {
        Ok(())
    } else {
        Err(CallbackError::InvalidReturnTo)
    }
}

fn is_public_suffix(host: &str) -> bool {
    const PUBLIC_SUFFIXES: &[&str] = &[
        "com", "org", "net", "edu", "gov", "mil", "int", "co", "ai", "io", "dev", "cloud", "app",
        "info", "biz", "name", "pro", "co.uk", "org.uk", "net.uk", "ac.uk", "gov.uk", "co.jp",
        "or.jp", "ne.jp", "go.jp", "de", "fr", "uk", "eu", "us",
    ];
    PUBLIC_SUFFIXES
        .iter()
        .any(|suffix| host.eq_ignore_ascii_case(suffix))
}

fn derive_saml_return_to(
    state: &CallbackState,
    relay_state: &str,
) -> Result<String, CallbackError> {
    // The portal encodes the final return URL in the SAML RelayState. If it is
    // not a valid URL, fall back to the gateway public base URL.
    if let Ok(url) = relay_state.parse::<reqwest::Url>()
        && validate_return_to(
            &state.allowed_return_to_hosts,
            state.tenant_allowed_return_to_hosts.as_deref(),
            state.local_dev_mode,
            url.as_str(),
        )
        .is_ok()
    {
        return Ok(relay_state.into());
    }
    Ok(state.public_base_url.clone())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::body::Body;
    use axum::http::Request;
    use base64::Engine;
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;
    use crate::db::{LoginStateRow, TenantConnectionRow};
    use crate::identity_provisioner::ProvisionError;
    use crate::jwks::JwksService;
    use crate::upstream_oauth::UpstreamTokenResponse;

    #[derive(Clone, Default)]
    struct StubLoginStateStore {
        state: Arc<Mutex<Option<Result<LoginStateRow, DbError>>>>,
        deleted: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl LoginStateStore for StubLoginStateStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _connection_id: &str,
            _connection_type: &str,
            _return_to: &str,
            _code_verifier: Option<String>,
            _nonce: Option<String>,
            _ttl: std::time::Duration,
        ) -> Result<LoginStateRow, DbError> {
            unimplemented!()
        }

        async fn get(&self, _state_token: &str) -> Result<LoginStateRow, DbError> {
            self.state
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn delete(&self, state_token: &str) -> Result<(), DbError> {
            self.deleted.lock().unwrap().push(state_token.to_string());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct StubConnectionStore {
        result: Arc<Mutex<Option<Result<TenantConnectionRow, DbError>>>>,
    }

    #[async_trait]
    impl TenantConnectionStore for StubConnectionStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _connection_type: crate::db::ConnectionType,
            _domain: &str,
            _config: serde_json::Value,
        ) -> Result<TenantConnectionRow, DbError> {
            unimplemented!()
        }

        async fn get_by_domain(&self, _domain: &str) -> Result<TenantConnectionRow, DbError> {
            unimplemented!()
        }

        async fn get_by_id(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<TenantConnectionRow, DbError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn list_by_tenant(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<TenantConnectionRow>, DbError> {
            unimplemented!()
        }

        async fn update_config(
            &self,
            _tenant_id: &str,
            _id: &str,
            _config: serde_json::Value,
        ) -> Result<TenantConnectionRow, DbError> {
            unimplemented!()
        }

        async fn set_enabled(
            &self,
            _tenant_id: &str,
            _id: &str,
            _is_enabled: bool,
        ) -> Result<TenantConnectionRow, DbError> {
            unimplemented!()
        }
    }

    #[derive(Clone, Default)]
    struct StubUpstreamOAuthClient {
        exchange_result: Arc<
            Mutex<Option<Result<UpstreamTokenResponse, crate::upstream_oauth::UpstreamOAuthError>>>,
        >,
        userinfo_result: Arc<
            Mutex<Option<Result<serde_json::Value, crate::upstream_oauth::UpstreamOAuthError>>>,
        >,
        exchange_calls: Arc<Mutex<Vec<Option<String>>>>,
    }

    #[async_trait]
    impl UpstreamOAuthClient for StubUpstreamOAuthClient {
        async fn exchange_code(
            &self,
            _config: &serde_json::Value,
            _code: &str,
            _redirect_uri: &str,
            code_verifier: Option<&str>,
        ) -> Result<UpstreamTokenResponse, crate::upstream_oauth::UpstreamOAuthError> {
            self.exchange_calls
                .lock()
                .unwrap()
                .push(code_verifier.map(String::from));
            self.exchange_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn fetch_userinfo(
            &self,
            _config: &serde_json::Value,
            _token_response: &UpstreamTokenResponse,
        ) -> Result<serde_json::Value, crate::upstream_oauth::UpstreamOAuthError> {
            self.userinfo_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }
    }

    #[derive(Clone, Default)]
    struct StubSessionStore;

    #[async_trait::async_trait]
    impl SessionStore for StubSessionStore {
        async fn create(
            &self,
            _session_id: &str,
            _sub: &str,
            _tenant_id: &str,
            _amr: &str,
            _expires_at: time::OffsetDateTime,
        ) -> Result<(), DbError> {
            Ok(())
        }

        async fn is_active(&self, _session_id: &str) -> Result<bool, DbError> {
            Ok(true)
        }

        async fn revoke(&self, _session_id: &str) -> Result<(), DbError> {
            Ok(())
        }

        async fn revoke_all_for_subject(&self, _sub: &str) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct StubIdentityProvisioner {
        result: Arc<Mutex<Option<Result<ProvisionedIdentity, ProvisionError>>>>,
    }

    #[async_trait]
    impl IdentityProvisioner for StubIdentityProvisioner {
        async fn provision(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
            _claims: &serde_json::Value,
        ) -> Result<ProvisionedIdentity, ProvisionError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn provision_saml(
            &self,
            tenant_id: &str,
            _provider_id: &str,
            _schema_id: &str,
            _name_id: &str,
            _email: &str,
            _email_verified: bool,
            _trusted_provider: bool,
        ) -> Result<ProvisionedIdentity, ProvisionError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
                .map(|mut identity| {
                    identity.tenant_id = tenant_id.into();
                    identity
                })
        }
    }

    fn test_rsa_key_pair() -> &'static (String, String) {
        static KEY_PAIR: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
        KEY_PAIR.get_or_init(|| {
            use rand::rngs::OsRng;
            use rsa::pkcs1::EncodeRsaPublicKey;
            use rsa::pkcs8::EncodePrivateKey;
            use rsa::{RsaPrivateKey, RsaPublicKey};

            let private_key =
                RsaPrivateKey::new(&mut OsRng, 2048).expect("failed to generate RSA test key");
            let public_key = RsaPublicKey::from(&private_key);
            let private_pem = private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::default())
                .expect("failed to encode private key")
                .to_string();
            let public_pem = public_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::default())
                .expect("failed to encode public key")
                .to_string();
            (private_pem, public_pem)
        })
    }

    fn sign_id_token(claims: serde_json::Value, kid: Option<&str>) -> String {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        let mut header = Header::new(Algorithm::RS256);
        header.kid = kid.map(String::from);
        let encoding_key =
            EncodingKey::from_rsa_pem(test_rsa_key_pair().0.as_bytes()).expect("valid RSA key");
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("token signing failed")
    }

    #[derive(Clone)]
    struct StubJwksService {
        public_pem: String,
    }

    #[async_trait]
    impl JwksService for StubJwksService {
        async fn decoding_key_for_token(
            &self,
            _id_token: &str,
            _jwks_url: &str,
        ) -> Result<jsonwebtoken::DecodingKey, CallbackError> {
            jsonwebtoken::DecodingKey::from_rsa_pem(self.public_pem.as_bytes())
                .map_err(|_| CallbackError::InvalidIdToken)
        }
    }

    fn test_state() -> Arc<CallbackState> {
        Arc::new(CallbackState {
            login_state: Arc::new(StubLoginStateStore::default()),
            connections: Arc::new(StubConnectionStore::default()),
            upstream_oauth: Arc::new(StubUpstreamOAuthClient::default()),
            identity_provisioner: Arc::new(StubIdentityProvisioner::default()),
            jwks_service: Arc::new(StubJwksService {
                public_pem: test_rsa_key_pair().1.clone(),
            }),
            saml: None,
            session_signer: SessionTokenSigner::new(
                "test-secret-that-is-at-least-32-bytes-long",
                3600,
                "https://gateway.example.com",
            ),
            session_store: Arc::new(StubSessionStore),
            allowed_return_to_hosts: vec!["app.example.com".into()],
            tenant_allowed_return_to_hosts: None,
            public_base_url: "https://gateway.example.com".into(),
            cookie_secure: true,
            cookie_samesite: "Lax".into(),
            session_ttl_seconds: 86400,
            local_dev_mode: true,
        })
    }

    fn test_state_with_login(result: Result<LoginStateRow, DbError>) -> Arc<CallbackState> {
        let mut state = test_state();
        let store = StubLoginStateStore {
            state: Arc::new(Mutex::new(Some(result))),
            deleted: Arc::new(Mutex::new(Vec::new())),
        };
        // SAFETY: we just constructed the Arc and know it is uniquely owned.
        let state_mut = Arc::get_mut(&mut state).unwrap();
        state_mut.login_state = Arc::new(store);
        state
    }

    fn test_state_with_connection(state: &mut Arc<CallbackState>, row: TenantConnectionRow) {
        let store = StubConnectionStore {
            result: Arc::new(Mutex::new(Some(Ok(row)))),
        };
        let state_mut = Arc::get_mut(state).unwrap();
        state_mut.connections = Arc::new(store);
    }

    fn test_state_with_upstream(
        state: &mut Arc<CallbackState>,
        token: UpstreamTokenResponse,
        userinfo: serde_json::Value,
    ) {
        let store = StubUpstreamOAuthClient {
            exchange_result: Arc::new(Mutex::new(Some(Ok(token)))),
            userinfo_result: Arc::new(Mutex::new(Some(Ok(userinfo)))),
            ..Default::default()
        };
        let state_mut = Arc::get_mut(state).unwrap();
        state_mut.upstream_oauth = Arc::new(store);
    }

    fn test_state_with_provisioner(state: &mut Arc<CallbackState>, identity: ProvisionedIdentity) {
        let store = StubIdentityProvisioner {
            result: Arc::new(Mutex::new(Some(Ok(identity)))),
        };
        let state_mut = Arc::get_mut(state).unwrap();
        state_mut.identity_provisioner = Arc::new(store);
    }

    fn login_row(connection_type: &str) -> LoginStateRow {
        LoginStateRow {
            state_token: "state-1".into(),
            tenant_id: "tenant-1".into(),
            connection_id: "conn-1".into(),
            connection_type: connection_type.into(),
            return_to: "https://app.example.com/dashboard".into(),
            code_verifier: None,
            nonce: None,
            created_at: time::OffsetDateTime::now_utc(),
            expires_at: time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(900),
        }
    }

    fn connection_row() -> TenantConnectionRow {
        TenantConnectionRow {
            id: "conn-1".into(),
            tenant_id: "tenant-1".into(),
            connection_type: crate::db::ConnectionType::Oidc,
            domain: "idp.example.com".into(),
            config: json!({
                "client_id": "client-1",
                "client_secret": "secret-1",
                "token_url": "https://idp.example.com/token",
                "userinfo_url": "https://idp.example.com/userinfo",
                "jwks_url": "https://idp.example.com/.well-known/jwks.json",
                "issuer": "https://idp.example.com",
            }),
            is_enabled: true,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    #[tokio::test]
    async fn oidc_callback_redirects_on_success() {
        let mut state = test_state_with_login(Ok(login_row("oidc")));
        test_state_with_connection(&mut state, connection_row());
        test_state_with_upstream(
            &mut state,
            UpstreamTokenResponse {
                access_token: "token-1".into(),
                token_type: "Bearer".into(),
                id_token: None,
                raw: json!({"access_token": "token-1"}),
            },
            json!({"email": "alice@example.com"}),
        );
        test_state_with_provisioner(
            &mut state,
            ProvisionedIdentity {
                tenant_id: "tenant-1".into(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: "alice@example.com".into(),
            },
        );
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oidc?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "https://app.example.com/dashboard"
        );
        let set_cookie = response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.starts_with("__Host-sso_session="));
    }

    #[tokio::test]
    async fn oauth2_callback_rejects_wrong_state_type() {
        let state = test_state_with_login(Ok(login_row("oidc")));
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oauth2?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oidc_callback_rejects_invalid_return_to() {
        let mut state = test_state_with_login(Ok({
            let mut row = login_row("oidc");
            row.return_to = "https://evil.example.com".into();
            row
        }));
        test_state_with_connection(&mut state, connection_row());
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oidc?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oauth2_callback_sends_code_verifier() {
        let mut state = test_state_with_login(Ok({
            let mut row = login_row("oauth2");
            row.code_verifier = Some("verifier-1".into());
            row
        }));
        test_state_with_connection(&mut state, {
            let mut row = connection_row();
            row.connection_type = crate::db::ConnectionType::OAuth2;
            row
        });
        test_state_with_upstream(
            &mut state,
            UpstreamTokenResponse {
                access_token: "token-1".into(),
                token_type: "Bearer".into(),
                id_token: None,
                raw: json!({"access_token": "token-1"}),
            },
            json!({"email": "alice@example.com"}),
        );
        test_state_with_provisioner(
            &mut state,
            ProvisionedIdentity {
                tenant_id: "tenant-1".into(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: "alice@example.com".into(),
            },
        );
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oauth2?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND);
    }

    #[tokio::test]
    async fn oidc_callback_validates_nonce() {
        let mut state = test_state_with_login(Ok({
            let mut row = login_row("oidc");
            row.nonce = Some("nonce-1".into());
            row
        }));
        test_state_with_connection(&mut state, connection_row());

        let id_token = sign_id_token(
            json!({
                "iss": "https://idp.example.com",
                "aud": "client-1",
                "exp": jsonwebtoken::get_current_timestamp() + 300,
                "nonce": "nonce-1",
            }),
            None,
        );
        test_state_with_upstream(
            &mut state,
            UpstreamTokenResponse {
                access_token: "token-1".into(),
                token_type: "Bearer".into(),
                id_token: Some(id_token),
                raw: json!({"access_token": "token-1", "id_token": "id-1"}),
            },
            json!({"email": "alice@example.com"}),
        );
        test_state_with_provisioner(
            &mut state,
            ProvisionedIdentity {
                tenant_id: "tenant-1".into(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: "alice@example.com".into(),
            },
        );
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oidc?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND);
    }

    #[tokio::test]
    async fn oidc_callback_rejects_bad_nonce() {
        let mut state = test_state_with_login(Ok({
            let mut row = login_row("oidc");
            row.nonce = Some("nonce-1".into());
            row
        }));
        test_state_with_connection(&mut state, connection_row());

        let id_token = sign_id_token(
            json!({
                "iss": "https://idp.example.com",
                "aud": "client-1",
                "exp": jsonwebtoken::get_current_timestamp() + 300,
                "nonce": "nonce-evil",
            }),
            None,
        );
        test_state_with_upstream(
            &mut state,
            UpstreamTokenResponse {
                access_token: "token-1".into(),
                token_type: "Bearer".into(),
                id_token: Some(id_token),
                raw: json!({"access_token": "token-1"}),
            },
            json!({"email": "alice@example.com"}),
        );
        test_state_with_provisioner(
            &mut state,
            ProvisionedIdentity {
                tenant_id: "tenant-1".into(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: "alice@example.com".into(),
            },
        );
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oidc?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_return_to_allows_exact_host() {
        assert!(
            validate_return_to(
                &["app.example.com".into()],
                None,
                true,
                "https://app.example.com/x"
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_return_to_rejects_unlisted_subdomain() {
        assert!(
            validate_return_to(
                &["example.com".into()],
                None,
                true,
                "https://app.example.com/x"
            )
            .is_err()
        );
    }

    #[test]
    fn validate_return_to_rejects_untrusted_host() {
        assert!(
            validate_return_to(&["example.com".into()], None, true, "https://evil.com/x").is_err()
        );
    }

    #[test]
    fn validate_return_to_rejects_empty_allowlist() {
        assert!(validate_return_to(&[], None, true, "https://app.example.com/x").is_err());
    }

    #[test]
    fn validate_return_to_rejects_http_in_production() {
        assert!(
            validate_return_to(
                &["app.example.com".into()],
                None,
                false,
                "http://app.example.com/x"
            )
            .is_err()
        );
    }

    #[test]
    fn validate_return_to_rejects_public_suffix_allowlist() {
        assert!(
            validate_return_to(&["com".into()], None, true, "https://app.example.com/x").is_err()
        );
        assert!(validate_return_to(&["co.uk".into()], None, true, "https://app.co.uk/x").is_err());
    }

    #[test]
    fn validate_return_to_accepts_tenant_host() {
        let tenant_hosts = vec!["tenant.example.com".into()];
        assert!(
            validate_return_to(
                &["example.com".into()],
                Some(&tenant_hosts),
                true,
                "https://tenant.example.com/x"
            )
            .is_ok()
        );

        // Tenant host should be rejected when tenant list is not provided.
        assert!(
            validate_return_to(
                &["example.com".into()],
                None,
                true,
                "https://tenant.example.com/x"
            )
            .is_err()
        );
    }

    #[derive(Clone, Default)]
    struct StubSamlAcsService {
        result: Arc<Mutex<Option<Result<ProvisionedIdentity, sunbeam_g2v::error::ServiceError>>>>,
    }

    #[async_trait]
    impl SamlAcsService for StubSamlAcsService {
        async fn process_saml_assertion_http(
            &self,
            _encoded_assertion: &str,
            _relay_state: &str,
        ) -> Result<ProvisionedIdentity, sunbeam_g2v::error::ServiceError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }
    }

    fn test_state_with_saml(state: &mut Arc<CallbackState>, identity: ProvisionedIdentity) {
        let saml = StubSamlAcsService {
            result: Arc::new(Mutex::new(Some(Ok(identity)))),
        };
        let state_mut = Arc::get_mut(state).unwrap();
        state_mut.saml = Some(Arc::new(saml));
    }

    #[tokio::test]
    async fn saml_acs_callback_redirects_on_success() {
        let mut state = test_state_with_login(Ok(login_row("saml")));
        test_state_with_saml(
            &mut state,
            ProvisionedIdentity {
                tenant_id: "tenant-1".into(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: "alice@example.com".into(),
            },
        );
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/saml/acs")
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from("SAMLResponse=cmVzcG9uc2U&RelayState=state-1"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND);
        let set_cookie = response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.starts_with("__Host-sso_session="));
    }

    #[tokio::test]
    async fn saml_acs_callback_rejects_missing_saml_response() {
        let state = test_state_with_login(Ok(login_row("saml")));
        let app = router(state);
        let response = app
            .oneshot(
                Request::post("/saml/acs")
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from("RelayState=state-1"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oidc_callback_rejects_missing_state() {
        let state = test_state_with_login(Ok(login_row("oidc")));
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oidc?code=code-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oidc_callback_rejects_expired_state() {
        let state = test_state_with_login(Err(DbError::LoginStateNotFound));
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oidc?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn build_session_cookie_has_expected_attributes() {
        let cookie = build_session_cookie("value-1", true, "Lax", 3600);
        assert!(cookie.contains("__Host-sso_session=value-1"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Max-Age=3600"));
    }

    #[tokio::test]
    async fn oidc_callback_rejects_unsigned_id_token() {
        let mut state = test_state_with_login(Ok(login_row("oidc")));
        test_state_with_connection(&mut state, connection_row());

        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "https://idp.example.com",
                "aud": "client-1",
                "exp": jsonwebtoken::get_current_timestamp() + 300,
            })
            .to_string()
            .as_bytes(),
        );
        let id_token = format!("eyJhbGciOiJub25lIn0.{payload}.signature");
        test_state_with_upstream(
            &mut state,
            UpstreamTokenResponse {
                access_token: "token-1".into(),
                token_type: "Bearer".into(),
                id_token: Some(id_token.clone()),
                raw: json!({"access_token": "token-1", "id_token": id_token}),
            },
            json!({"email": "alice@example.com"}),
        );
        test_state_with_provisioner(
            &mut state,
            ProvisionedIdentity {
                tenant_id: "tenant-1".into(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: "alice@example.com".into(),
            },
        );
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oidc?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oidc_callback_rejects_wrong_issuer() {
        let mut state = test_state_with_login(Ok(login_row("oidc")));
        test_state_with_connection(&mut state, connection_row());

        let id_token = sign_id_token(
            json!({
                "iss": "https://evil.example.com",
                "aud": "client-1",
                "exp": jsonwebtoken::get_current_timestamp() + 300,
            }),
            None,
        );
        test_state_with_upstream(
            &mut state,
            UpstreamTokenResponse {
                access_token: "token-1".into(),
                token_type: "Bearer".into(),
                id_token: Some(id_token),
                raw: json!({"access_token": "token-1"}),
            },
            json!({"email": "alice@example.com"}),
        );
        test_state_with_provisioner(
            &mut state,
            ProvisionedIdentity {
                tenant_id: "tenant-1".into(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: "alice@example.com".into(),
            },
        );
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oidc?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oidc_callback_rejects_expired_id_token() {
        let mut state = test_state_with_login(Ok(login_row("oidc")));
        test_state_with_connection(&mut state, connection_row());

        let id_token = sign_id_token(
            json!({
                "iss": "https://idp.example.com",
                "aud": "client-1",
                "exp": jsonwebtoken::get_current_timestamp() - 300,
            }),
            None,
        );
        test_state_with_upstream(
            &mut state,
            UpstreamTokenResponse {
                access_token: "token-1".into(),
                token_type: "Bearer".into(),
                id_token: Some(id_token),
                raw: json!({"access_token": "token-1"}),
            },
            json!({"email": "alice@example.com"}),
        );
        test_state_with_provisioner(
            &mut state,
            ProvisionedIdentity {
                tenant_id: "tenant-1".into(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: "alice@example.com".into(),
            },
        );
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oidc?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oidc_callback_rejects_wrong_signature() {
        let mut state = test_state_with_login(Ok(login_row("oidc")));
        test_state_with_connection(&mut state, connection_row());

        // Replace the JWKS service with one that uses a different public key.
        let wrong_key_pair = {
            use rand::rngs::OsRng;
            use rsa::pkcs1::EncodeRsaPublicKey;
            use rsa::pkcs8::EncodePrivateKey;
            use rsa::{RsaPrivateKey, RsaPublicKey};

            let private_key =
                RsaPrivateKey::new(&mut OsRng, 2048).expect("failed to generate RSA test key");
            let public_key = RsaPublicKey::from(&private_key);
            let private_pem = private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::default())
                .expect("failed to encode private key")
                .to_string();
            let public_pem = public_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::default())
                .expect("failed to encode public key")
                .to_string();
            (private_pem, public_pem)
        };
        {
            let state_mut = Arc::get_mut(&mut state).unwrap();
            state_mut.jwks_service = Arc::new(StubJwksService {
                public_pem: wrong_key_pair.1,
            });
        }

        let id_token = sign_id_token(
            json!({
                "iss": "https://idp.example.com",
                "aud": "client-1",
                "exp": jsonwebtoken::get_current_timestamp() + 300,
            }),
            None,
        );
        test_state_with_upstream(
            &mut state,
            UpstreamTokenResponse {
                access_token: "token-1".into(),
                token_type: "Bearer".into(),
                id_token: Some(id_token),
                raw: json!({"access_token": "token-1"}),
            },
            json!({"email": "alice@example.com"}),
        );
        test_state_with_provisioner(
            &mut state,
            ProvisionedIdentity {
                tenant_id: "tenant-1".into(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: "alice@example.com".into(),
            },
        );
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/callbacks/oidc?code=code-1&state=state-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
