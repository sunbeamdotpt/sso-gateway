use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Extension, Form, Json, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use sso_ory_client::{error::OryClientError, hydra::HydraClient, kratos::KratosClient};
use tracing::{instrument, warn};
use ulid::Ulid;

use crate::auth::{
    AuthContext, SCOPE_APPLICATION_ADMIN, SCOPE_TENANT_ADMIN, hash_token,
    resolve_tenant_from_subject,
};
use crate::db::{IdMappingRepo, IdMappingStore, TokenIntrospectionCache};
use crate::services::application::{
    BACKEND_HYDRA, validate_native_redirect_uris, validate_redirect_uris,
    validate_token_endpoint_auth_method,
};

/// Async trait for the Hydra operations used by the public OAuth2/OIDC handlers.
#[async_trait]
pub trait HydraOperations: Send + Sync + 'static {
    async fn authorize(
        &self,
        query: Vec<(String, String)>,
        cookie: Option<&str>,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn token(
        &self,
        form: Vec<(String, String)>,
        client_credentials: Option<(String, String)>,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn device(
        &self,
        path: &str,
        form: Vec<(String, String)>,
        client_credentials: Option<(String, String)>,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn get_device_verify(
        &self,
        query: Vec<(String, String)>,
        cookie: Option<&str>,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn userinfo(&self, token: &str) -> Result<serde_json::Value, OryClientError>;
    async fn introspect_token(&self, token: &str) -> Result<serde_json::Value, OryClientError>;
    async fn verify_client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<bool, OryClientError>;
    async fn revoke(&self, form: Vec<(String, String)>) -> Result<(), OryClientError>;
    async fn create_oauth2_client(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn get_oauth2_client(&self, id: &str) -> Result<serde_json::Value, OryClientError>;
    /// Full-replacement client update (Hydra PUT). Only used by the
    /// authorize-time Matrix scope self-heal, which treats any failure as
    /// warn-and-proceed, so stubs may keep the default.
    async fn update_oauth2_client(
        &self,
        _id: &str,
        _payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        Err(OryClientError::InvalidResponse(
            "update_oauth2_client not supported".into(),
        ))
    }
    async fn get_json(&self, url: reqwest::Url) -> Result<serde_json::Value, OryClientError>;
    fn public_url(&self) -> &reqwest::Url;
}

#[async_trait]
impl HydraOperations for HydraClient {
    async fn authorize(
        &self,
        query: Vec<(String, String)>,
        cookie: Option<&str>,
    ) -> Result<serde_json::Value, OryClientError> {
        self.authorize(query, cookie).await
    }

    async fn token(
        &self,
        form: Vec<(String, String)>,
        client_credentials: Option<(String, String)>,
    ) -> Result<serde_json::Value, OryClientError> {
        let creds = client_credentials
            .as_ref()
            .map(|(id, secret)| (id.as_str(), secret.as_str()));
        self.token(form, creds).await
    }

    async fn device(
        &self,
        path: &str,
        form: Vec<(String, String)>,
        client_credentials: Option<(String, String)>,
    ) -> Result<serde_json::Value, OryClientError> {
        let creds = client_credentials
            .as_ref()
            .map(|(id, secret)| (id.as_str(), secret.as_str()));
        self.device(path, form, creds).await
    }

    async fn get_device_verify(
        &self,
        query: Vec<(String, String)>,
        cookie: Option<&str>,
    ) -> Result<serde_json::Value, OryClientError> {
        self.get_device_verify(query, cookie).await
    }

    async fn userinfo(&self, token: &str) -> Result<serde_json::Value, OryClientError> {
        self.userinfo(token).await
    }

    async fn introspect_token(&self, token: &str) -> Result<serde_json::Value, OryClientError> {
        self.introspect_token(token).await
    }

    async fn verify_client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<bool, OryClientError> {
        self.verify_client_credentials(client_id, client_secret)
            .await
    }

    async fn revoke(&self, form: Vec<(String, String)>) -> Result<(), OryClientError> {
        self.revoke(form).await
    }

    async fn create_oauth2_client(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.create_oauth2_client(payload).await
    }

    async fn get_oauth2_client(&self, id: &str) -> Result<serde_json::Value, OryClientError> {
        self.get_oauth2_client(id).await
    }

    async fn update_oauth2_client(
        &self,
        id: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.update_oauth2_client(id, payload).await
    }

    async fn get_json(&self, url: reqwest::Url) -> Result<serde_json::Value, OryClientError> {
        self.get_json(url).await
    }

    fn public_url(&self) -> &reqwest::Url {
        self.public_url()
    }
}

/// Kratos operations used by the public OAuth2/OIDC handlers.
///
/// Separate from the consent service's `ConsentKratos` seam: introspection
/// only needs identity traits for the Matrix email injection.
#[async_trait]
pub trait IntrospectKratos: Send + Sync + 'static {
    async fn get_identity(&self, id: &str) -> Result<serde_json::Value, OryClientError>;
}

#[async_trait]
impl IntrospectKratos for KratosClient {
    async fn get_identity(&self, id: &str) -> Result<serde_json::Value, OryClientError> {
        self.get_identity(id).await
    }
}

/// State shared by the OAuth2/OIDC HTTP handlers.
#[derive(Clone)]
pub struct Oauth2State {
    pub(crate) hydra: Arc<dyn HydraOperations>,
    pub(crate) mappings: Arc<dyn IdMappingStore>,
    pub(crate) public_base_url: String,
    pub(crate) token_cache: Option<Arc<dyn TokenIntrospectionCache>>,
    /// Tenant under which publicly registered (RFC 7591) clients are mapped.
    pub(crate) system_tenant_id: String,
    /// Whether public dynamic client registration (RFC 7591) is enabled.
    pub(crate) dynamic_client_registration_enabled: bool,
    /// Kratos access for the introspection email injection (Matrix).
    pub(crate) kratos: Option<Arc<dyn IntrospectKratos>>,
    /// Clients whose introspection responses always carry the user's email.
    pub(crate) force_email_claim_client_ids: Vec<String>,
    /// Whether the MSC2965 `urn:matrix:client:` scope-prefix match injects
    /// the email claim into introspection responses.
    pub(crate) matrix_email_claim_enabled: bool,
    /// Whether Matrix-shaped authorize requests get `offline_access` appended
    /// and Matrix DCR registrations keep the refresh-token grant.
    pub(crate) matrix_offline_access_enabled: bool,
}

impl Oauth2State {
    pub fn new(hydra: Arc<HydraClient>, mappings: IdMappingRepo, public_base_url: String) -> Self {
        Self {
            hydra: hydra as Arc<dyn HydraOperations>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            public_base_url,
            token_cache: None,
            system_tenant_id: String::new(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        }
    }

    pub fn with_token_cache(mut self, cache: Arc<dyn TokenIntrospectionCache>) -> Self {
        self.token_cache = Some(cache);
        self
    }

    pub fn with_system_tenant_id(mut self, system_tenant_id: String) -> Self {
        self.system_tenant_id = system_tenant_id;
        self
    }

    pub fn with_dynamic_client_registration_enabled(mut self, enabled: bool) -> Self {
        self.dynamic_client_registration_enabled = enabled;
        self
    }

    pub fn with_kratos(mut self, kratos: Arc<KratosClient>) -> Self {
        self.kratos = Some(kratos as Arc<dyn IntrospectKratos>);
        self
    }

    pub fn with_force_email_claim_client_ids(mut self, client_ids: Vec<String>) -> Self {
        self.force_email_claim_client_ids = client_ids;
        self
    }

    pub fn with_matrix_email_claim_enabled(mut self, enabled: bool) -> Self {
        self.matrix_email_claim_enabled = enabled;
        self
    }

    pub fn with_matrix_offline_access_enabled(mut self, enabled: bool) -> Self {
        self.matrix_offline_access_enabled = enabled;
        self
    }
}

pub fn router(state: Arc<Oauth2State>) -> Router {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth2/auth", get(authorize))
        .route("/oauth2/token", post(token))
        .route("/oauth2/device/verify", get(device_verify))
        .route("/oauth2/device/{*path}", post(device))
        .route("/oauth2/userinfo", get(userinfo))
        .route("/userinfo", get(userinfo))
        .route("/oauth2/register", post(register))
        .route("/oauth2/introspect", post(introspect))
        .route("/oauth2/revoke", post(revoke))
        .layer(axum::middleware::from_fn(cors_middleware))
        .with_state(state)
}

/// Minimal CORS handling for the public OAuth2/OIDC surface.
///
/// Browser clients (e.g. Matrix Element) preflight dynamic client
/// registration and the token endpoints; without an answer the browser kills
/// the request before it ever reaches Hydra. Hand-rolled to avoid pulling in
/// tower-http for a single fixed policy.
async fn cors_middleware(request: Request, next: Next) -> Response {
    use axum::http::header;
    if request.method() == axum::http::Method::OPTIONS {
        return (
            StatusCode::NO_CONTENT,
            [
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
                (
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    "authorization, content-type",
                ),
                (header::ACCESS_CONTROL_MAX_AGE, "7200"),
            ],
        )
            .into_response();
    }
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        axum::http::HeaderValue::from_static("*"),
    );
    response
}

fn base_url(public_base_url: &str) -> String {
    public_base_url.trim_end_matches('/').to_string()
}

/// Decode an HTTP Basic Authorization header into `(client_id, client_secret)`.
fn basic_auth_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let header = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, payload) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

async fn openid_configuration(State(state): State<Arc<Oauth2State>>) -> impl IntoResponse {
    let base = base_url(&state.public_base_url);
    let mut body = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth2/auth"),
        "token_endpoint": format!("{base}/oauth2/token"),
        "device_authorization_endpoint": format!("{base}/oauth2/device/auth"),
        "userinfo_endpoint": format!("{base}/oauth2/userinfo"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "introspection_endpoint": format!("{base}/oauth2/introspect"),
        "revocation_endpoint": format!("{base}/oauth2/revoke"),
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "grant_types_supported": ["authorization_code", "implicit", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        "code_challenge_methods_supported": ["S256"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
    });
    if state.dynamic_client_registration_enabled {
        body["registration_endpoint"] = json!(format!("{base}/oauth2/register"));
    }
    json_response(body)
}

async fn jwks(State(state): State<Arc<Oauth2State>>) -> impl IntoResponse {
    let url = match state
        .hydra
        .public_url()
        .join(".well-known/jwks.json")
        .map_err(OryClientError::Url)
    {
        Ok(url) => url,
        Err(err) => return map_ory_error(err, "/.well-known/jwks.json", None),
    };

    match state.hydra.get_json(url).await {
        Ok(keys) => json_response(keys),
        Err(err) => map_ory_error(err, "/.well-known/jwks.json", None),
    }
}

async fn authorize(
    State(state): State<Arc<Oauth2State>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Hydra's CSRF/continuity cookies must reach Hydra on the post-login and
    // post-consent authorize round-trips, or Hydra rejects the request with
    // "No CSRF value available in the session cookie". HTTP/2 clients may
    // split cookies across multiple Cookie header fields (RFC 7540 §8.1.2.5),
    // so reassemble them with "; " before forwarding.
    let joined = headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    let cookie = if joined.is_empty() {
        None
    } else {
        Some(joined)
    };
    // Guardrail replacing the DCR ceiling that Matrix `*` registrations drop:
    // a Matrix-shaped authorize request may carry only plain-OIDC scopes and
    // `urn:matrix:client:`-prefixed scopes, so anonymous DCR clients cannot
    // consent-phish admin scopes through their `*` registration. Stateless
    // and client-agnostic; non-Matrix requests are unaffected.
    if let Some(offending) = params
        .get("scope")
        .and_then(|scope| disallowed_matrix_scope(scope))
    {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "error": "invalid_scope",
                "error_description": format!(
                    "scope '{offending}' is not allowed alongside {MATRIX_CLIENT_SCOPE_PREFIX}* scopes"
                ),
            })),
        )
            .into_response();
    }
    let client_id = params.get("client_id").cloned().unwrap_or_default();
    let ory_id = match resolve_public_client_for_authorize(&state, &client_id).await {
        Ok(id) => id,
        Err(err) => return *err,
    };

    // Self-heal Matrix clients whose registration predates the wildcard DCR
    // rule (e.g. Element Web/Desktop, whose DCR request carries no Matrix
    // scopes at all) before the scope is checked by Hydra. Coverage is
    // measured against the effective scope, including the offline_access
    // appended below.
    let scope = params.get("scope").cloned().unwrap_or_default();
    let effective_scope = with_matrix_offline_access(&state, &scope);
    let requested: Vec<&str> = effective_scope.split_whitespace().collect();
    if requested
        .iter()
        .any(|s| s.starts_with(MATRIX_CLIENT_SCOPE_PREFIX))
    {
        maybe_expand_matrix_client_scope(&state, &ory_id, &requested).await;
    }

    let query = params
        .into_iter()
        .map(|(k, v)| {
            if k == "client_id" {
                (k, ory_id.clone())
            } else if k == "scope" {
                // Deliberate MSC2965 exception: Matrix native clients request
                // only `openid urn:matrix:client:*` — never `offline_access` —
                // so their sessions would die at the access-token TTL. Any
                // Matrix-shaped authorize request gets `offline_access`
                // appended here, making the scope legitimately requested so
                // consent grants it naturally and Hydra issues a refresh token.
                (k, effective_scope.clone())
            } else {
                (k, v)
            }
        })
        .collect::<Vec<_>>();
    match state.hydra.authorize(query, cookie.as_deref()).await {
        Ok(value) => json_response(value),
        Err(OryClientError::Redirect {
            location,
            set_cookies,
        }) => {
            if location.is_empty() {
                return internal_error();
            }
            let Ok(location) = axum::http::HeaderValue::try_from(location) else {
                return internal_error();
            };
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(axum::http::header::LOCATION, location);
            for cookie in set_cookies {
                if let Ok(value) = axum::http::HeaderValue::try_from(cookie) {
                    headers.append(axum::http::header::SET_COOKIE, value);
                }
            }
            (StatusCode::FOUND, headers, Body::empty()).into_response()
        }
        Err(err) => map_ory_error(err, "/oauth2/auth", Some(&client_id)),
    }
}

async fn token(
    State(state): State<Arc<Oauth2State>>,
    headers: HeaderMap,
    Form(mut form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let client_credentials = if let Some((id, secret)) = basic_auth_credentials(&headers) {
        // Avoid sending credentials twice: use the Basic header and drop any
        // duplicate values from the form body.
        form.remove("client_id");
        form.remove("client_secret");
        Some((id, secret))
    } else {
        None
    };

    let client_id = client_credentials
        .as_ref()
        .map(|(id, _)| id.clone())
        .or_else(|| form.get("client_id").cloned())
        .unwrap_or_default();
    if client_id.is_empty() {
        return bad_request("missing client_id");
    }
    let ory_id = match resolve_public_client(&state, &client_id).await {
        Ok(id) => id,
        Err(err) => return *err,
    };

    let hydra_credentials = client_credentials.map(|(_, secret)| (ory_id.clone(), secret));
    form.insert("client_id".to_string(), ory_id);

    match state
        .hydra
        .token(form.into_iter().collect(), hydra_credentials)
        .await
    {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err, "/oauth2/token", Some(&client_id)),
    }
}

async fn device(
    State(state): State<Arc<Oauth2State>>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Form(mut form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let client_credentials = if let Some((id, secret)) = basic_auth_credentials(&headers) {
        form.remove("client_id");
        form.remove("client_secret");
        Some((id, secret))
    } else {
        None
    };

    let client_id = client_credentials
        .as_ref()
        .map(|(id, _)| id.clone())
        .or_else(|| form.get("client_id").cloned())
        .unwrap_or_default();
    if client_id.is_empty() {
        return bad_request("missing client_id");
    }
    let ory_id = match resolve_public_client(&state, &client_id).await {
        Ok(id) => id,
        Err(err) => return *err,
    };

    let hydra_credentials = client_credentials.map(|(_, secret)| (ory_id.clone(), secret));
    form.insert("client_id".to_string(), ory_id);

    match state
        .hydra
        .device(&path, form.into_iter().collect(), hydra_credentials)
        .await
    {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err, &format!("/oauth2/device/{path}"), Some(&client_id)),
    }
}

async fn device_verify(
    State(state): State<Arc<Oauth2State>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Hydra's device CSRF cookie must reach Hydra on the post-accept
    // verification leg, or Hydra rejects the request. HTTP/2 clients may split
    // cookies across multiple Cookie header fields (RFC 7540 §8.1.2.5), so
    // reassemble them with "; " before forwarding.
    let joined = headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    let cookie = if joined.is_empty() {
        None
    } else {
        Some(joined)
    };

    // The post-accept leg carries the gateway's public client id; translate it
    // back before forwarding. The initial user-code leg has no client_id.
    let client_id = params.get("client_id").cloned();
    let mut query = Vec::with_capacity(params.len());
    for (k, v) in params {
        if k == "client_id" {
            let ory_id = match resolve_public_client(&state, &v).await {
                Ok(id) => id,
                Err(err) => return *err,
            };
            query.push((k, ory_id));
        } else {
            query.push((k, v));
        }
    }

    match state
        .hydra
        .get_device_verify(query, cookie.as_deref())
        .await
    {
        Ok(value) => json_response(value),
        Err(OryClientError::Redirect {
            location,
            set_cookies,
        }) => {
            if location.is_empty() {
                return internal_error();
            }
            let Ok(location) = axum::http::HeaderValue::try_from(location) else {
                return internal_error();
            };
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(axum::http::header::LOCATION, location);
            for cookie in set_cookies {
                if let Ok(value) = axum::http::HeaderValue::try_from(cookie) {
                    headers.append(axum::http::header::SET_COOKIE, value);
                }
            }
            (StatusCode::FOUND, headers, String::new()).into_response()
        }
        Err(err) => map_ory_error(err, "/oauth2/device/verify", client_id.as_deref()),
    }
}

async fn userinfo(State(state): State<Arc<Oauth2State>>, headers: HeaderMap) -> impl IntoResponse {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => return unauthorized(),
    };

    let mut value = match state.hydra.userinfo(token).await {
        Ok(value) => value,
        Err(err) => return map_ory_error(err, "/oauth2/userinfo", None),
    };

    if let Some(obj) = value.as_object_mut()
        && let Some(sub) = obj.get("sub").and_then(|v| v.as_str())
        && let Some(public_id) = translate_ory_id_to_public_id(&state, sub).await
    {
        obj.insert("sub".to_string(), json!(public_id));
    }

    json_response(value)
}

/// Scopes a publicly registered (RFC 7591) client may hold. Registration is
/// open — there is no way to distinguish e.g. a Matrix client from anyone
/// else at DCR time — so the ceiling keeps anonymous clients inside the
/// plain OIDC surface. MSC2965 `urn:matrix:client:*` scopes are exempt:
/// per-device Matrix registrations cannot be enumerated, so they pass
/// through verbatim (see `register`).
const DCR_ALLOWED_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

async fn register(
    State(state): State<Arc<Oauth2State>>,
    auth: Option<Extension<AuthContext>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !state.dynamic_client_registration_enabled {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "access_denied",
                "error_description": "dynamic client registration is disabled",
            })),
        )
            .into_response();
    }

    let redirect_uris = json_string_array(&body["redirect_uris"]);
    let mut grant_types = json_string_array(&body["grant_types"]);
    let response_types = json_string_array(&body["response_types"]);
    // MSC2965 exception to the DCR ceiling: `urn:matrix:client:*` scopes are
    // preserved verbatim (per-device registrations can't be enumerated), and
    // when the offline-access feature is on the client also gets the
    // `offline_access` scope and the `refresh_token` grant so Matrix sessions
    // can outlive the access-token TTL. Non-Matrix registrations keep the
    // plain-OIDC ceiling exactly.
    let mut scope = body["scope"]
        .as_str()
        .map(|s| {
            s.split_whitespace()
                .filter(|s| {
                    DCR_ALLOWED_SCOPES.contains(s) || s.starts_with(MATRIX_CLIENT_SCOPE_PREFIX)
                })
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if scope.is_empty() {
        scope.push("openid".to_string());
    }
    if grant_types.is_empty() {
        grant_types.push("authorization_code".to_string());
    }
    let is_matrix = scope
        .iter()
        .any(|s| s.starts_with(MATRIX_CLIENT_SCOPE_PREFIX));
    if is_matrix && state.matrix_offline_access_enabled {
        if !scope.iter().any(|s| s == "offline_access") {
            scope.push("offline_access".to_string());
        }
        if !grant_types.iter().any(|g| g == "refresh_token") {
            grant_types.push("refresh_token".to_string());
        }
    }
    // Hydra exact-matches requested scopes against the registered scope (no
    // wildcards), and Matrix 1.19 clients request a per-login
    // `urn:matrix:client:device:<id>` scope that can never be pre-registered —
    // so a Matrix client's registered scope must match everything. The legacy
    // shared Matrix client uses `*` for the same reason. The authorize
    // handler's Matrix scope guardrail replaces the ceiling this drops. The
    // response echoes the effective registered scope, as RFC 7591 expects.
    let registered_scope = if is_matrix {
        "*".to_string()
    } else {
        scope.join(" ")
    };
    let token_endpoint_auth_method = body["token_endpoint_auth_method"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if let Err(err) = validate_token_endpoint_auth_method(&token_endpoint_auth_method) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "invalid_request", "error_description": err.to_string()})),
        )
            .into_response();
    }
    // Public clients (token_endpoint_auth_method "none") get RFC 8252 native
    // redirect rules — custom URI schemes like io.element.android:/ — while
    // confidential clients keep the https-only web rules.
    let redirect_validation = if token_endpoint_auth_method == "none" {
        validate_native_redirect_uris(&redirect_uris)
    } else {
        validate_redirect_uris(&redirect_uris, false)
    };
    if let Err(err) = redirect_validation {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "invalid_request", "error_description": err.to_string()})),
        )
            .into_response();
    }

    let client_name = body["client_name"].as_str().unwrap_or("").to_string();
    let public_id = Ulid::new().to_string();
    let payload = json!({
        "client_id": public_id,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types.clone(),
        "response_types": if response_types.is_empty() { vec!["code".to_string()] } else { response_types.clone() },
        "scope": registered_scope.clone(),
        "token_endpoint_auth_method": token_endpoint_auth_method,
    });

    let created = match state.hydra.create_oauth2_client(payload).await {
        Ok(value) => value,
        Err(err) => return map_ory_error(err, "/oauth2/register", None),
    };

    let ory_id = match created["client_id"].as_str() {
        Some(id) => id,
        None => return internal_error(),
    };
    let client_secret = created["client_secret"].as_str().unwrap_or("").to_string();

    // An authenticated caller (opportunistic bearer on the public route)
    // owns the mapping under its own tenant; anonymous DCR clients map under
    // the system tenant.
    let tenant_id = auth
        .as_ref()
        .map(|Extension(a)| a.tenant_id.clone())
        .unwrap_or_else(|| state.system_tenant_id.clone());

    match state
        .mappings
        .create(&tenant_id, BACKEND_HYDRA, &public_id, ory_id)
        .await
    {
        Ok(_) => {}
        Err(err) => {
            warn!(
                tenant_id = %tenant_id,
                public_id = %public_id,
                "failed to store client mapping: {}",
                err
            );
            return internal_error();
        }
    }

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let response = json!({
        "client_id": public_id,
        "client_secret": client_secret,
        "client_id_issued_at": now,
        "client_secret_expires_at": 0,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "scope": registered_scope,
        "token_endpoint_auth_method": token_endpoint_auth_method,
    });
    json_response(response)
}

fn json_string_array(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

async fn revoke(
    State(state): State<Arc<Oauth2State>>,
    headers: HeaderMap,
    Form(mut form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = form.get("token").cloned();

    let client_credentials = if let Some((id, secret)) = basic_auth_credentials(&headers) {
        form.remove("client_id");
        form.remove("client_secret");
        Some((id, secret))
    } else {
        None
    };

    let client_id = client_credentials
        .as_ref()
        .map(|(id, _)| id.clone())
        .or_else(|| form.get("client_id").cloned())
        .unwrap_or_default();
    if !client_id.is_empty() {
        match resolve_public_client(&state, &client_id).await {
            Ok(ory_id) => {
                let hydra_credentials =
                    client_credentials.map(|(_, secret)| (ory_id.clone(), secret));
                form.insert("client_id".to_string(), ory_id);
                if let Some((id, secret)) = hydra_credentials {
                    form.insert("client_secret".to_string(), secret);
                    let _ = id;
                }
            }
            Err(err) => return *err,
        }
    }

    let form_vec = form.into_iter().collect::<Vec<_>>();

    match state.hydra.revoke(form_vec).await {
        Ok(()) => {
            if let Some(token) = token
                && let Some(cache) = &state.token_cache
            {
                let token_hash = hash_token(&token);
                if let Err(e) = cache.remove(&token_hash).await {
                    warn!("failed to clear token introspection cache after revocation: {e}");
                }
            }
            StatusCode::OK.into_response()
        }
        Err(err) => map_ory_error(
            err,
            "/oauth2/revoke",
            if client_id.is_empty() {
                None
            } else {
                Some(client_id.as_str())
            },
        ),
    }
}

async fn introspect(
    State(state): State<Arc<Oauth2State>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = match form.get("token") {
        Some(t) => t.clone(),
        None => return bad_request("missing token"),
    };

    let mut value = if let Some((client_id, secret)) = basic_auth_credentials(&headers) {
        // Client-authenticated introspection (RFC 7662). Hydra serves
        // introspection on its admin port only, so the gateway verifies the
        // client credentials itself before using the admin endpoint.
        let ory_id = match resolve_public_client(&state, &client_id).await {
            Ok(id) => id,
            Err(err) => return *err,
        };
        match state
            .hydra
            .verify_client_credentials(&ory_id, &secret)
            .await
        {
            Ok(true) => {}
            Ok(false) => return invalid_client(),
            Err(err) => return map_ory_error(err, "/oauth2/introspect", Some(&client_id)),
        }
        match state.hydra.introspect_token(&token).await {
            Ok(value) => value,
            Err(err) => return map_ory_error(err, "/oauth2/introspect", Some(&client_id)),
        }
    } else {
        // Bearer-authenticated admin introspection keeps using the Hydra
        // admin endpoint behind a scope check.
        let Extension(auth) = match auth {
            Some(auth) => auth,
            None => return unauthorized(),
        };
        if !auth
            .scopes
            .iter()
            .any(|s| s == SCOPE_TENANT_ADMIN || s == SCOPE_APPLICATION_ADMIN)
        {
            return forbidden();
        }
        match state.hydra.introspect_token(&token).await {
            Ok(value) => value,
            Err(err) => return map_ory_error(err, "/oauth2/introspect", None),
        }
    };

    if !value
        .get("active")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return json_response(value);
    }

    let subject = match value.get("sub").and_then(|v| v.as_str()) {
        Some(sub) => sub.to_string(),
        None => return json_response(value),
    };

    match resolve_tenant_from_subject(state.mappings.as_ref(), &subject).await {
        Ok(tenant_id) => {
            // Capture the raw Hydra client_id before translation: the email
            // force-list match accepts both the raw and the public form.
            let raw_client_id = value
                .get("client_id")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            if let Some(obj) = value.as_object_mut() {
                obj.insert("tenant_id".to_string(), json!(tenant_id));
                if let Some(public_id) = translate_ory_id_to_public_id(&state, &subject).await {
                    obj.insert("sub".to_string(), json!(public_id));
                }
                if let Some(client_id) = obj.get("client_id").and_then(|v| v.as_str())
                    && let Some(public_id) = translate_ory_id_to_public_id(&state, client_id).await
                {
                    obj.insert("client_id".to_string(), json!(public_id));
                }
            }
            maybe_inject_introspection_email(&state, &subject, raw_client_id.as_deref(), &mut value)
                .await;
            json_response(value)
        }
        Err(crate::auth::AuthError::UnknownSubject) => {
            warn!("introspected token has active=true but no tenant mapping; treating as inactive");
            json_response(json!({"active": false}))
        }
        Err(err) => {
            warn!("failed to resolve tenant for introspected token: {}", err);
            internal_error()
        }
    }
}

/// MSC2965 Matrix client scope family. Matrix OIDC tokens always carry a
/// `urn:matrix:client:`-prefixed scope (e.g. `urn:matrix:client:api:*`),
/// which identifies Matrix-issued tokens — including per-device DCR clients
/// that no static client-id list could enumerate.
const MATRIX_CLIENT_SCOPE_PREFIX: &str = "urn:matrix:client:";

/// Guardrail for Matrix-shaped authorize requests (see `authorize`): when any
/// requested scope carries the MSC2965 prefix, every requested scope must be
/// plain-OIDC or Matrix-prefixed. Returns the first offending scope.
fn disallowed_matrix_scope(scope: &str) -> Option<String> {
    let scopes: Vec<&str> = scope.split_whitespace().collect();
    if !scopes
        .iter()
        .any(|s| s.starts_with(MATRIX_CLIENT_SCOPE_PREFIX))
    {
        return None;
    }
    scopes
        .iter()
        .find(|s| {
            !matches!(**s, "openid" | "profile" | "email" | "offline_access")
                && !s.starts_with(MATRIX_CLIENT_SCOPE_PREFIX)
        })
        .map(|s| s.to_string())
}

/// Self-heal for Matrix (MSC2965) clients whose Hydra registration predates
/// the wildcard DCR rule — notably Element Web/Desktop, whose DCR request
/// carries no `urn:matrix:client:` scopes, so the client registered as plain
/// `openid` and every Matrix-shaped authorize dies with `invalid_scope`
/// (Hydra exact-matches scopes). When the registered scope does not cover the
/// requested set, the client is expanded to scope `*` (same as the legacy
/// shared Matrix client and the DCR-time rule) and, when offline access is
/// enabled, gains the `refresh_token` grant — those clients registered with
/// only `authorization_code`, and fosite checks grants separately at the
/// token endpoint. Hydra's client PUT is full-replacement, so the update
/// merges against the fetched client. Every failure is warn-and-proceed:
/// Hydra's `invalid_scope` is the same failure the request had without the
/// heal. Already-covering clients (e.g. scope `*`) skip the write entirely.
async fn maybe_expand_matrix_client_scope(
    state: &Oauth2State,
    ory_id: &str,
    requested_scopes: &[&str],
) {
    let client = match state.hydra.get_oauth2_client(ory_id).await {
        Ok(client) => client,
        Err(err) => {
            // Includes the raw pass-through case from
            // resolve_public_client_for_authorize, where the client may not
            // exist in Hydra at all.
            warn!(
                client_id = %ory_id,
                "matrix scope self-heal: failed to fetch client; proxying unhealed: {err}"
            );
            return;
        }
    };
    let registered: Vec<&str> = client["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    let covered = registered.contains(&"*")
        || requested_scopes.iter().all(|s| registered.contains(s));
    if covered {
        return;
    }

    let mut payload = client.clone();
    payload["scope"] = json!("*");
    if state.matrix_offline_access_enabled {
        let mut grant_types: Vec<String> = client["grant_types"]
            .as_array()
            .map(|grants| {
                grants
                    .iter()
                    .filter_map(|g| g.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if !grant_types.iter().any(|g| g == "refresh_token") {
            grant_types.push("refresh_token".to_string());
            payload["grant_types"] = json!(grant_types);
        }
    }
    if let Err(err) = state.hydra.update_oauth2_client(ory_id, payload).await {
        warn!(
            client_id = %ory_id,
            "matrix scope self-heal: failed to expand client; proxying unhealed: {err}"
        );
    }
}

/// Append `offline_access` to an authorize-request scope string when it
/// carries a Matrix (MSC2965) scope and the feature is enabled. An absent or
/// already-offline scope is returned untouched.
fn with_matrix_offline_access(state: &Oauth2State, scope: &str) -> String {
    let mut scopes: Vec<&str> = scope.split_whitespace().collect();
    if !state.matrix_offline_access_enabled
        || scopes.is_empty()
        || !scopes
            .iter()
            .any(|s| s.starts_with(MATRIX_CLIENT_SCOPE_PREFIX))
        || scopes.contains(&"offline_access")
    {
        return scope.to_string();
    }
    scopes.push("offline_access");
    scopes.join(" ")
}

/// Inject the user's email into an active introspection response.
///
/// Matrix homeservers (zendrite) never read the id_token; they validate
/// tokens through this introspection response, so the email must ride here.
/// Injection happens for Matrix-shaped tokens (MSC2965 scope family) and for
/// clients on the configured force list, matched against both the raw Hydra
/// client id and its translated public ULID. Failures never fail the
/// introspection: a machine-client subject (no Kratos identity), a Kratos
/// error, or a missing `traits.email` all yield the response without the
/// claim.
async fn maybe_inject_introspection_email(
    state: &Oauth2State,
    raw_sub: &str,
    raw_client_id: Option<&str>,
    value: &mut serde_json::Value,
) {
    let Some(kratos) = &state.kratos else {
        return;
    };
    let scope = value
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let is_matrix_token = state.matrix_email_claim_enabled
        && scope
            .split_whitespace()
            .any(|s| s.starts_with(MATRIX_CLIENT_SCOPE_PREFIX));
    let translated_client_id = value.get("client_id").and_then(|v| v.as_str());
    let is_force_listed = state.force_email_claim_client_ids.iter().any(|id| {
        Some(id.as_str()) == raw_client_id || Some(id.as_str()) == translated_client_id
    });
    if !is_matrix_token && !is_force_listed {
        return;
    }
    match kratos.get_identity(raw_sub).await {
        Ok(identity) => match identity_email(&identity) {
            Some(email) => {
                if let Some(obj) = value.as_object_mut() {
                    obj.insert("email".to_string(), json!(email));
                }
            }
            None => tracing::debug!(
                subject = %raw_sub,
                "introspected subject has no email trait; response returned without it"
            ),
        },
        Err(err) => warn!(
            subject = %raw_sub,
            "failed to fetch identity for introspection email injection; response returned without it: {err}"
        ),
    }
}

/// Extract the base identity email from a Kratos identity payload. Email is
/// the Kratos identifier, so it always lives in `traits.email`.
fn identity_email(identity: &serde_json::Value) -> Option<String> {
    identity
        .get("traits")?
        .get("email")?
        .as_str()
        .map(str::to_string)
}

async fn resolve_public_client(
    state: &Oauth2State,
    client_id: &str,
) -> Result<String, Box<Response>> {
    if client_id.is_empty() {
        return Err(Box::new(bad_request("missing client_id")));
    }

    match state
        .mappings
        .get_ory_id_by_public_id(BACKEND_HYDRA, client_id)
        .await
    {
        Ok(ory_id) => Ok(ory_id),
        Err(crate::db::DbError::MappingNotFound) => {
            heal_client_mapping(state, client_id).await
        }
        Err(e) => {
            warn!("failed to resolve public client {}: {}", client_id, e);
            Err(Box::new(internal_error()))
        }
    }
}

/// Self-healing client resolution (SSO-015): a client may legitimately exist
/// in Hydra while its id_mapping row is missing (registered out-of-band, or
/// the row was lost). If Hydra knows the client, backfill the mapping under
/// the system tenant and carry on; a Hydra 404 stays a terminal
/// `401 invalid_client`.
async fn heal_client_mapping(state: &Oauth2State, client_id: &str) -> Result<String, Box<Response>> {
    let client = match state.hydra.get_oauth2_client(client_id).await {
        Ok(client) => client,
        Err(OryClientError::Ory { status: 404, .. }) => {
            return Err(Box::new(
                (
                    StatusCode::UNAUTHORIZED,
                    json!({"error": "invalid_client"}).to_string(),
                )
                    .into_response(),
            ));
        }
        Err(err) => {
            warn!("failed to look up client {} in hydra: {}", client_id, err);
            return Err(Box::new(internal_error()));
        }
    };
    let ory_id = client["client_id"]
        .as_str()
        .unwrap_or(client_id)
        .to_string();
    if let Err(err) = state
        .mappings
        .create(&state.system_tenant_id, BACKEND_HYDRA, client_id, &ory_id)
        .await
    {
        // A racing replica may have written the row first; the client id is
        // resolved either way, so the backfill failure is not terminal.
        warn!("failed to backfill client mapping for {}: {}", client_id, err);
    }
    Ok(ory_id)
}

/// Resolve a gateway public client id to the Ory id. If the value is already an
/// Ory id (e.g. because Hydra generated it in a redirect URL) pass it through
/// unchanged. This is only appropriate for the public OAuth2 authorization
/// endpoint where Hydra itself produces the client_id query parameter.
async fn resolve_public_client_for_authorize(
    state: &Oauth2State,
    client_id: &str,
) -> Result<String, Box<Response>> {
    if client_id.is_empty() {
        return Err(Box::new(bad_request("missing client_id")));
    }

    match state
        .mappings
        .get_ory_id_by_public_id(BACKEND_HYDRA, client_id)
        .await
    {
        Ok(ory_id) => Ok(ory_id),
        Err(crate::db::DbError::MappingNotFound) => Ok(client_id.to_string()),
        Err(e) => {
            warn!("failed to resolve public client {}: {}", client_id, e);
            Err(Box::new(internal_error()))
        }
    }
}

async fn translate_ory_id_to_public_id(state: &Oauth2State, ory_id: &str) -> Option<String> {
    for backend in [BACKEND_HYDRA, "kratos"] {
        if let Ok(public_id) = state
            .mappings
            .get_public_id_by_ory_id(backend, ory_id)
            .await
        {
            return Some(public_id);
        }
    }
    None
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
}

fn json_response(value: serde_json::Value) -> Response<Body> {
    (StatusCode::OK, axum::Json(value)).into_response()
}

fn bad_request(message: &str) -> Response<Body> {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({"error": "invalid_request", "error_description": message})),
    )
        .into_response()
}

fn unauthorized() -> Response<Body> {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

fn invalid_client() -> Response<Body> {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "invalid_client"})),
    )
        .into_response()
}

fn forbidden() -> Response<Body> {
    (
        StatusCode::FORBIDDEN,
        axum::Json(json!({"error": "forbidden"})),
    )
        .into_response()
}

fn internal_error() -> Response<Body> {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({"error": "server_error"})),
    )
        .into_response()
}

/// Map an Ory backend error to an HTTP response.
///
/// Hydra's 4xx bodies follow RFC 6749 §5.2 and are meant for the client, so
/// they are relayed verbatim — a caller staring at `invalid_scope` can fix its
/// own request, while `server_error` sends it spelunking through gateway logs.
/// 5xx and transport failures stay opaque to avoid leaking internals.
#[instrument(skip(err))]
fn map_ory_error(err: OryClientError, path: &str, client_id: Option<&str>) -> Response<Body> {
    let (status, body) = match &err {
        OryClientError::Ory {
            status, message, ..
        } => {
            let ory_status = *status;
            let status = match ory_status {
                400 => StatusCode::BAD_REQUEST,
                401 => StatusCode::UNAUTHORIZED,
                403 => StatusCode::FORBIDDEN,
                404 => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_GATEWAY,
            };
            (status, relay_client_error_body(ory_status, message))
        }
        OryClientError::Http(_) | OryClientError::Url(_) => {
            (StatusCode::BAD_GATEWAY, server_error_body())
        }
        OryClientError::Serialization(_) | OryClientError::InvalidResponse(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, server_error_body())
        }
        OryClientError::MissingTenant => (StatusCode::UNAUTHORIZED, server_error_body()),
        OryClientError::Redirect { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, server_error_body())
        }
    };
    warn!(
        ?err,
        %path,
        client_id = client_id.unwrap_or_default(),
        "ory backend error"
    );
    (status, axum::Json(body)).into_response()
}

fn server_error_body() -> serde_json::Value {
    json!({"error": "server_error"})
}

/// Relay a Hydra 4xx body verbatim when it is a JSON object carrying an
/// `error` field (the RFC 6749 §5.2 shape); anything else stays opaque.
fn relay_client_error_body(status: u16, message: &str) -> serde_json::Value {
    if (400..500).contains(&status)
        && let Ok(body) = serde_json::from_str::<serde_json::Value>(message)
        && body.get("error").and_then(|e| e.as_str()).is_some()
    {
        return body;
    }
    server_error_body()
}

#[cfg(test)]
mod tests {
    use crate::auth::SubjectType;
    use super::*;
    use axum::http::HeaderValue;
    use tower::ServiceExt;

    #[derive(Default)]
    struct StubHydra;

    #[async_trait]
    impl HydraOperations for StubHydra {
        async fn authorize(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub authorize not configured")
        }

        async fn get_device_verify(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub get_device_verify not configured")
        }

        async fn token(
            &self,
            _form: Vec<(String, String)>,
            _client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub token not configured")
        }

        async fn device(
            &self,
            _path: &str,
            _form: Vec<(String, String)>,
            _client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub device not configured")
        }

        async fn userinfo(&self, _token: &str) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub userinfo not configured")
        }

        async fn introspect_token(
            &self,
            _token: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub introspect_token not configured")
        }

        async fn verify_client_credentials(
            &self,
            _client_id: &str,
            _client_secret: &str,
        ) -> Result<bool, OryClientError> {
            unimplemented!("stub verify_client_credentials not configured")
        }

        async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
            unimplemented!("stub revoke not configured")
        }

        async fn create_oauth2_client(
            &self,
            _payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub create_oauth2_client not configured")
        }

        async fn get_oauth2_client(
            &self,
            _id: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            Err(OryClientError::Ory {
                status: 404,
                message: "not found".into(),
            })
        }

        async fn get_json(&self, _url: reqwest::Url) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub get_json not configured")
        }

        fn public_url(&self) -> &reqwest::Url {
            unimplemented!("stub public_url not configured")
        }
    }

    #[derive(Clone, Default)]
    #[allow(clippy::type_complexity)]
    struct StubMappingStore {
        tenant_by_ory_id: Arc<std::sync::Mutex<Option<Result<Option<String>, crate::db::DbError>>>>,
        ory_by_public_id: Arc<std::sync::Mutex<Option<Result<Option<String>, crate::db::DbError>>>>,
        public_id_by_ory_id:
            Arc<std::sync::Mutex<Option<Result<Option<String>, crate::db::DbError>>>>,
    }

    impl StubMappingStore {
        fn with_ory_by_public_id(result: Result<Option<String>, crate::db::DbError>) -> Self {
            Self {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(None)),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(Some(result))),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(None)),
            }
        }
    }

    #[async_trait]
    impl IdMappingStore for StubMappingStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
            _ory_global_id: &str,
        ) -> Result<crate::db::IdMappingRow, crate::db::DbError> {
            Err(crate::db::DbError::ConnectionNotFound)
        }

        async fn get_ory_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<String, crate::db::DbError> {
            Err(crate::db::DbError::ConnectionNotFound)
        }

        async fn get_ory_id_by_public_id(
            &self,
            _backend: &str,
            _public_id: &str,
        ) -> Result<String, crate::db::DbError> {
            let guard = self.ory_by_public_id.lock().unwrap();
            match guard.as_ref().expect("stub not configured") {
                Ok(Some(id)) => Ok(id.clone()),
                Ok(None) => Err(crate::db::DbError::MappingNotFound),
                Err(_) => Err(crate::db::DbError::ConnectionNotFound),
            }
        }

        async fn get_public_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, crate::db::DbError> {
            Err(crate::db::DbError::ConnectionNotFound)
        }

        async fn get_public_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, crate::db::DbError> {
            let guard = self.public_id_by_ory_id.lock().unwrap();
            match guard.as_ref().expect("stub not configured") {
                Ok(Some(id)) => Ok(id.clone()),
                Ok(None) => Err(crate::db::DbError::MappingNotFound),
                Err(_) => Err(crate::db::DbError::ConnectionNotFound),
            }
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<(), crate::db::DbError> {
            Err(crate::db::DbError::ConnectionNotFound)
        }

        async fn list_public_ids(
            &self,
            _tenant_id: &str,
            _backend: &str,
        ) -> Result<Vec<String>, crate::db::DbError> {
            Ok(vec![])
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, crate::db::DbError> {
            let guard = self.tenant_by_ory_id.lock().unwrap();
            match guard.as_ref().expect("stub not configured") {
                Ok(tenant) => Ok(tenant.clone()),
                Err(_) => Err(crate::db::DbError::ConnectionNotFound),
            }
        }
    }

    #[derive(Clone, Default)]
    struct MockTokenCache {
        removed: Arc<std::sync::Mutex<Vec<String>>>,
        fail_remove: Arc<std::sync::Mutex<bool>>,
    }

    impl MockTokenCache {
        fn with_remove_error() -> Self {
            Self {
                removed: Arc::new(std::sync::Mutex::new(Vec::new())),
                fail_remove: Arc::new(std::sync::Mutex::new(true)),
            }
        }
    }

    #[async_trait]
    impl TokenIntrospectionCache for MockTokenCache {
        async fn get(
            &self,
            _token_hash: &str,
            _max_age: time::Duration,
        ) -> Result<Option<crate::db::TokenIntrospectionRow>, crate::db::DbError> {
            Ok(None)
        }

        async fn put(
            &self,
            _token_hash: &str,
            _active: bool,
            _sub: Option<&str>,
            _scope: Option<&str>,
            _exp: Option<time::OffsetDateTime>,
        ) -> Result<(), crate::db::DbError> {
            Ok(())
        }

        async fn remove(&self, token_hash: &str) -> Result<(), crate::db::DbError> {
            self.removed.lock().unwrap().push(token_hash.to_string());
            if *self.fail_remove.lock().unwrap() {
                Err(crate::db::DbError::ConnectionNotFound)
            } else {
                Ok(())
            }
        }
    }

    fn test_state(
        tenant_result: Option<Result<Option<String>, crate::db::DbError>>,
    ) -> Oauth2State {
        Oauth2State {
            hydra: Arc::new(StubHydra),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(tenant_result)),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "hydra-client-id-1".to_string(),
                ))))),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "gateway-public-1".to_string(),
                ))))),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        }
    }

    fn resolve_state(ory_result: Result<Option<String>, crate::db::DbError>) -> Oauth2State {
        Oauth2State {
            hydra: Arc::new(StubHydra),
            mappings: Arc::new(StubMappingStore::with_ory_by_public_id(ory_result)),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        }
    }

    async fn body_to_string(resp: Response<Body>) -> String {
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn base_url_trims_trailing_slash() {
        assert_eq!(base_url("https://example.com/"), "https://example.com");
        assert_eq!(base_url("https://example.com"), "https://example.com");
    }

    #[test]
    fn bearer_token_extracts_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token"),
        );
        assert_eq!(bearer_token(&headers), Some("secret-token"));
    }

    #[test]
    fn bearer_token_rejects_non_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn map_ory_error_sets_expected_status() {
        let resp = map_ory_error(OryClientError::MissingTenant, "/test", None);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = map_ory_error(OryClientError::InvalidResponse("fail".into()), "/test", None);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let resp = map_ory_error(
            OryClientError::Ory {
                status: 400,
                message: "bad".into(),
            },
            "/test",
            None,
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = map_ory_error(
            OryClientError::Ory {
                status: 401,
                message: "unauth".into(),
            },
            "/test",
            None,
        );
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = map_ory_error(
            OryClientError::Ory {
                status: 403,
                message: "forbidden".into(),
            },
            "/test",
            None,
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp = map_ory_error(
            OryClientError::Ory {
                status: 404,
                message: "not found".into(),
            },
            "/test",
            None,
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp = map_ory_error(
            OryClientError::Ory {
                status: 500,
                message: "down".into(),
            },
            "/test",
            None,
        );
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let resp = map_ory_error(
            OryClientError::Serialization(
                serde_json::from_str::<serde_json::Value>("not json").unwrap_err(),
            ),
            "/test",
            None,
        );
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn map_ory_error_http_and_url_variants() {
        let resp = map_ory_error(
            OryClientError::Http(reqwest::get("http://localhost:1").await.unwrap_err()),
            "/test",
            None,
        );
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let resp = map_ory_error(
            OryClientError::Url(reqwest::Url::parse("not-a-url").unwrap_err()),
            "/test",
            None,
        );
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn map_ory_error_body_is_generic() {
        let resp = map_ory_error(
            OryClientError::Ory {
                status: 500,
                message: "sensitive details".into(),
            },
            "/test",
            None,
        );
        let body = body_to_string(resp).await;
        assert!(body.contains("server_error"));
        assert!(!body.contains("sensitive details"));
    }

    #[tokio::test]
    async fn map_ory_error_relays_rfc6749_4xx_body_verbatim() {
        let resp = map_ory_error(
            OryClientError::Ory {
                status: 400,
                message: "{\"error\":\"invalid_scope\",\"error_description\":\"The requested scope is invalid: not allowed to request scope 'bogus:scope'.\"}".into(),
            },
            "/oauth2/device/auth",
            Some("client-1"),
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("invalid_scope"));
        assert!(body.contains("bogus:scope"));
        assert!(!body.contains("server_error"));
    }

    #[tokio::test]
    async fn map_ory_error_relays_device_flow_authorization_pending() {
        let resp = map_ory_error(
            OryClientError::Ory {
                status: 400,
                message: "{\"error\":\"authorization_pending\",\"error_description\":\"The authorization request is still pending.\"}".into(),
            },
            "/oauth2/token",
            Some("client-1"),
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("authorization_pending"));
    }

    #[tokio::test]
    async fn map_ory_error_opaque_when_4xx_body_not_rfc_shaped() {
        let resp = map_ory_error(
            OryClientError::Ory {
                status: 400,
                message: "<html>proxy error</html>".into(),
            },
            "/test",
            None,
        );
        let body = body_to_string(resp).await;
        assert!(body.contains("server_error"));
        assert!(!body.contains("proxy error"));
    }

    #[tokio::test]
    async fn map_ory_error_keeps_5xx_opaque_even_with_rfc_body() {
        let resp = map_ory_error(
            OryClientError::Ory {
                status: 500,
                message: "{\"error\":\"internal\",\"error_description\":\"db connection string leaked\"}".into(),
            },
            "/test",
            None,
        );
        let body = body_to_string(resp).await;
        assert!(body.contains("server_error"));
        assert!(!body.contains("db connection string leaked"));
    }

    #[tokio::test]
    async fn json_response_returns_ok_json() {
        let resp = json_response(json!({"key": "value"}));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn bad_request_contains_error_description() {
        let resp = bad_request("missing foo");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("invalid_request"));
        assert!(body.contains("missing foo"));
    }

    #[tokio::test]
    async fn unauthorized_returns_expected_json() {
        let resp = unauthorized();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_to_string(resp).await;
        assert!(body.contains("unauthorized"));
    }

    #[tokio::test]
    async fn internal_error_returns_expected_json() {
        let resp = internal_error();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_to_string(resp).await;
        assert!(body.contains("server_error"));
    }

    #[test]
    fn base_url_trims_multiple_trailing_slashes() {
        assert_eq!(base_url("https://example.com///"), "https://example.com");
    }

    #[test]
    fn bearer_token_rejects_invalid_utf8_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
        );
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn map_ory_error_maps_ory_409_to_bad_gateway() {
        let resp = map_ory_error(
            OryClientError::Ory {
                status: 409,
                message: "conflict".into(),
            },
            "/test",
            None,
        );
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn map_ory_error_maps_unknown_ory_status_to_bad_gateway() {
        let resp = map_ory_error(
            OryClientError::Ory {
                status: 503,
                message: "unavailable".into(),
            },
            "/test",
            None,
        );
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn resolve_public_client_rejects_missing_client_id() {
        let state = resolve_state(Ok(None));
        let err = resolve_public_client(&state, "").await.unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(*err).await;
        assert!(body.contains("missing client_id"));
    }

    #[tokio::test]
    async fn resolve_public_client_rejects_unknown_client() {
        let state = resolve_state(Ok(None));
        let err = resolve_public_client(&state, "unknown-client")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        let body = body_to_string(*err).await;
        assert!(body.contains("invalid_client"));
    }

    #[tokio::test]
    async fn resolve_public_client_returns_ory_id_for_registered_client() {
        let state = test_state(Some(Ok(Some("tenant-a".to_string()))));
        let ory_id = resolve_public_client(&state, "client-1").await.unwrap();
        assert_eq!(ory_id, "hydra-client-id-1");
    }

    #[tokio::test]
    async fn resolve_public_client_maps_db_error_to_internal() {
        let state = resolve_state(Err(crate::db::DbError::ConnectionNotFound));
        let err = resolve_public_client(&state, "client-1").await.unwrap_err();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn resolve_public_client_backfills_mapping_when_hydra_has_client() {
        let mappings = Arc::new(RecordingMappingStore::default());
        let state = Oauth2State {
            hydra: Arc::new(AlwaysOkHydra {
                response: json!({"client_id": "hydra-generated-id"}),
            }),
            mappings: mappings.clone(),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        };
        let ory_id = resolve_public_client(&state, "external-client")
            .await
            .unwrap();
        assert_eq!(ory_id, "hydra-generated-id");
        let created = mappings.created.lock().unwrap();
        assert_eq!(created.len(), 1);
        assert_eq!(
            created[0],
            (
                "system-tenant-1".to_string(),
                "hydra".to_string(),
                "external-client".to_string(),
                "hydra-generated-id".to_string(),
            )
        );
    }

    #[tokio::test]
    async fn resolve_public_client_returns_internal_when_hydra_lookup_fails() {
        let state = Oauth2State {
            hydra: Arc::new(AlwaysErrHydra),
            mappings: Arc::new(RecordingMappingStore::default()),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        };
        let err = resolve_public_client(&state, "external-client")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn authorize_returns_bad_request_when_client_id_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing client_id"));
    }

    /// Hydra stub that always returns a JSON payload for every operation.
    #[derive(Clone, Default)]
    struct AlwaysOkHydra {
        response: serde_json::Value,
    }

    #[async_trait]
    impl HydraOperations for AlwaysOkHydra {
        async fn authorize(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn get_device_verify(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn token(
            &self,
            _form: Vec<(String, String)>,
            _client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn device(
            &self,
            _path: &str,
            _form: Vec<(String, String)>,
            _client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn userinfo(&self, _token: &str) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn introspect_token(
            &self,
            _token: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn verify_client_credentials(
            &self,
            _client_id: &str,
            client_secret: &str,
        ) -> Result<bool, OryClientError> {
            Ok(client_secret == "secret")
        }

        async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
            Ok(())
        }

        async fn create_oauth2_client(
            &self,
            _payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(json!({
                "client_id": "ory-client-1",
                "client_secret": "ory-secret-1",
            }))
        }

        async fn get_oauth2_client(
            &self,
            _id: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn get_json(&self, _url: reqwest::Url) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        fn public_url(&self) -> &reqwest::Url {
            static URL: std::sync::OnceLock<reqwest::Url> = std::sync::OnceLock::new();
            URL.get_or_init(|| reqwest::Url::parse("http://127.0.0.1:4444").unwrap())
        }
    }

    /// Hydra stub that records the normalized request passed to it.
    #[derive(Clone, Default)]
    #[allow(clippy::type_complexity)]
    struct RecordingHydra {
        response: serde_json::Value,
        authorize_calls: Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>>,
        authorize_cookies: Arc<std::sync::Mutex<Vec<Option<String>>>>,
        token_calls: Arc<std::sync::Mutex<Vec<(Vec<(String, String)>, Option<(String, String)>)>>>,
        device_calls:
            Arc<std::sync::Mutex<Vec<(String, Vec<(String, String)>, Option<(String, String)>)>>>,
        create_calls: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
        get_client_calls: Arc<std::sync::Mutex<Vec<String>>>,
        update_calls: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
        fail_update: bool,
    }

    #[async_trait]
    impl HydraOperations for RecordingHydra {
        async fn authorize(
            &self,
            query: Vec<(String, String)>,
            cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            self.authorize_calls.lock().unwrap().push(query);
            self.authorize_cookies
                .lock()
                .unwrap()
                .push(cookie.map(str::to_owned));
            Ok(self.response.clone())
        }

        async fn get_device_verify(
            &self,
            query: Vec<(String, String)>,
            cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            self.authorize_calls.lock().unwrap().push(query);
            self.authorize_cookies
                .lock()
                .unwrap()
                .push(cookie.map(str::to_owned));
            Ok(self.response.clone())
        }

        async fn token(
            &self,
            form: Vec<(String, String)>,
            client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            self.token_calls
                .lock()
                .unwrap()
                .push((form, client_credentials));
            Ok(self.response.clone())
        }

        async fn device(
            &self,
            path: &str,
            form: Vec<(String, String)>,
            client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            self.device_calls
                .lock()
                .unwrap()
                .push((path.to_string(), form, client_credentials));
            Ok(self.response.clone())
        }

        async fn userinfo(&self, _token: &str) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn introspect_token(
            &self,
            _token: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn verify_client_credentials(
            &self,
            _client_id: &str,
            client_secret: &str,
        ) -> Result<bool, OryClientError> {
            Ok(client_secret == "secret")
        }

        async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
            Ok(())
        }

        async fn create_oauth2_client(
            &self,
            payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            self.create_calls.lock().unwrap().push(payload);
            Ok(json!({
                "client_id": "ory-client-1",
                "client_secret": "ory-secret-1",
            }))
        }

        async fn get_oauth2_client(
            &self,
            id: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            self.get_client_calls.lock().unwrap().push(id.to_string());
            Ok(self.response.clone())
        }

        async fn update_oauth2_client(
            &self,
            id: &str,
            payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            self.update_calls
                .lock()
                .unwrap()
                .push((id.to_string(), payload.clone()));
            if self.fail_update {
                return Err(OryClientError::Ory {
                    status: 500,
                    message: "update failed".into(),
                });
            }
            Ok(payload)
        }

        async fn get_json(&self, _url: reqwest::Url) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        fn public_url(&self) -> &reqwest::Url {
            static URL: std::sync::OnceLock<reqwest::Url> = std::sync::OnceLock::new();
            URL.get_or_init(|| reqwest::Url::parse("http://127.0.0.1:4444").unwrap())
        }
    }

    fn ok_state(tenant: Option<String>) -> Oauth2State {
        Oauth2State {
            hydra: Arc::new(AlwaysOkHydra {
                response: json!({"status": "ok"}),
            }),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(tenant.map(|t| Ok(Some(t))))),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "hydra-client-id-1".to_string(),
                ))))),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "gateway-public-1".to_string(),
                ))))),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        }
    }

    #[tokio::test]
    async fn jwks_returns_ok() {
        let state = Arc::new(ok_state(None));
        let resp = jwks(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authorize_succeeds_for_valid_client() {
        let state = Arc::new(ok_state(Some("tenant-1".to_string())));
        let params = HashMap::from([("client_id".to_string(), "client-1".to_string())]);
        let resp = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Hydra stub that redirects `authorize` carrying a set of cookies, used to
    /// verify the handler forwards Hydra's `Set-Cookie` headers (notably the
    /// `oauth2_authentication_csrf` cookie) to the browser.
    #[derive(Clone, Default)]
    struct RedirectHydra {
        location: String,
        set_cookies: Vec<String>,
        inner: AlwaysOkHydra,
    }

    #[async_trait]
    impl HydraOperations for RedirectHydra {
        async fn authorize(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            Err(OryClientError::Redirect {
                location: self.location.clone(),
                set_cookies: self.set_cookies.clone(),
            })
        }

        async fn get_device_verify(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            Err(OryClientError::Redirect {
                location: self.location.clone(),
                set_cookies: self.set_cookies.clone(),
            })
        }

        async fn token(
            &self,
            form: Vec<(String, String)>,
            client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            self.inner.token(form, client_credentials).await
        }

        async fn device(
            &self,
            path: &str,
            form: Vec<(String, String)>,
            client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            self.inner.device(path, form, client_credentials).await
        }

        async fn userinfo(&self, token: &str) -> Result<serde_json::Value, OryClientError> {
            self.inner.userinfo(token).await
        }

        async fn introspect_token(&self, token: &str) -> Result<serde_json::Value, OryClientError> {
            self.inner.introspect_token(token).await
        }

        async fn verify_client_credentials(
            &self,
            client_id: &str,
            client_secret: &str,
        ) -> Result<bool, OryClientError> {
            self.inner
                .verify_client_credentials(client_id, client_secret)
                .await
        }

        async fn revoke(&self, form: Vec<(String, String)>) -> Result<(), OryClientError> {
            self.inner.revoke(form).await
        }

        async fn create_oauth2_client(
            &self,
            payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            self.inner.create_oauth2_client(payload).await
        }

        async fn get_oauth2_client(&self, id: &str) -> Result<serde_json::Value, OryClientError> {
            self.inner.get_oauth2_client(id).await
        }

        async fn get_json(&self, url: reqwest::Url) -> Result<serde_json::Value, OryClientError> {
            self.inner.get_json(url).await
        }

        fn public_url(&self) -> &reqwest::Url {
            self.inner.public_url()
        }
    }

    fn redirect_state(location: String, set_cookies: Vec<String>) -> Oauth2State {
        Oauth2State {
            hydra: Arc::new(RedirectHydra {
                location,
                set_cookies,
                inner: AlwaysOkHydra {
                    response: json!({"status": "ok"}),
                },
            }),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "tenant-1".to_string(),
                ))))),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "hydra-client-id-1".to_string(),
                ))))),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "gateway-public-1".to_string(),
                ))))),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        }
    }

    #[tokio::test]
    async fn authorize_forwards_set_cookie_on_redirect() {
        let state = Arc::new(redirect_state(
            "https://gateway.example.com/login?login_challenge=abc".to_string(),
            vec![
                "oauth2_authentication_csrf=a; Path=/; HttpOnly".to_string(),
                "ory_hydra_continuity=b; Path=/; HttpOnly".to_string(),
            ],
        ));
        let params = HashMap::from([("client_id".to_string(), "client-1".to_string())]);
        let resp = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert!(resp.headers().get(axum::http::header::LOCATION).is_some());
        let cookies: Vec<_> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .collect();
        assert_eq!(cookies.len(), 2);
    }

    /// Regression test: the browser's `Cookie` header must be forwarded to
    /// Hydra on `/oauth2/auth`, or Hydra rejects the post-login authorize with
    /// "No CSRF value available in the session cookie".
    #[tokio::test]
    async fn authorize_forwards_browser_cookie_to_hydra() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([("client_id".to_string(), "gateway-client-1".to_string())]);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static(
                "oauth2_authentication_csrf=csrf-value; ory_hydra_continuity=cont",
            ),
        );
        let _ = authorize(State(state), headers, Query(params))
            .await
            .into_response();
        let cookies = hydra.authorize_cookies.lock().unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            cookies[0].as_deref(),
            Some("oauth2_authentication_csrf=csrf-value; ory_hydra_continuity=cont")
        );
    }

    #[tokio::test]
    async fn authorize_passes_no_cookie_when_browser_sent_none() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([("client_id".to_string(), "gateway-client-1".to_string())]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let cookies = hydra.authorize_cookies.lock().unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0], None);
    }

    /// Regression: HTTP/2 clients may split cookies across multiple Cookie
    /// header fields (RFC 7540 §8.1.2.5); all fields must reach Hydra,
    /// reassembled with "; ", or a cookie in a later field (e.g. the freshly
    /// minted consent CSRF cookie) is silently dropped.
    #[tokio::test]
    async fn authorize_joins_split_cookie_headers() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([("client_id".to_string(), "gateway-client-1".to_string())]);
        let mut headers = HeaderMap::new();
        headers.append(
            axum::http::header::COOKIE,
            HeaderValue::from_static("ory_hydra_login_csrf=login-csrf"),
        );
        headers.append(
            axum::http::header::COOKIE,
            HeaderValue::from_static("oauth2_authentication_csrf=consent-csrf"),
        );
        let _ = authorize(State(state), headers, Query(params))
            .await
            .into_response();
        let cookies = hydra.authorize_cookies.lock().unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            cookies[0].as_deref(),
            Some("ory_hydra_login_csrf=login-csrf; oauth2_authentication_csrf=consent-csrf")
        );
    }

    #[tokio::test]
    async fn device_verify_forwards_set_cookie_on_redirect() {
        let state = Arc::new(redirect_state(
            "https://gateway.example.com/device?device_challenge=abc&user_code=ABCD-EFGH"
                .to_string(),
            vec!["ory_hydra_device_csrf=a; Path=/; HttpOnly".to_string()],
        ));
        let params = HashMap::from([("user_code".to_string(), "ABCD-EFGH".to_string())]);
        let resp = device_verify(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://gateway.example.com/device?device_challenge=abc&user_code=ABCD-EFGH")
        );
        let cookies: Vec<_> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .collect();
        assert_eq!(cookies.len(), 1);
    }

    /// The browser's `Cookie` header must reach Hydra on `/oauth2/device/verify`
    /// or Hydra rejects the post-accept leg with a CSRF error.
    #[tokio::test]
    async fn device_verify_forwards_browser_cookie_to_hydra() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([("user_code".to_string(), "ABCD-EFGH".to_string())]);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("ory_hydra_device_csrf=device-csrf"),
        );
        let _ = device_verify(State(state), headers, Query(params))
            .await
            .into_response();
        let cookies = hydra.authorize_cookies.lock().unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            cookies[0].as_deref(),
            Some("ory_hydra_device_csrf=device-csrf")
        );
    }

    /// Same RFC 7540 §8.1.2.5 split-cookie hazard as `/oauth2/auth`: all Cookie
    /// fields must reach Hydra reassembled with "; ".
    #[tokio::test]
    async fn device_verify_joins_split_cookie_headers() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([("user_code".to_string(), "ABCD-EFGH".to_string())]);
        let mut headers = HeaderMap::new();
        headers.append(
            axum::http::header::COOKIE,
            HeaderValue::from_static("ory_hydra_device_csrf=device-csrf"),
        );
        headers.append(
            axum::http::header::COOKIE,
            HeaderValue::from_static("ory_kratos_session=session"),
        );
        let _ = device_verify(State(state), headers, Query(params))
            .await
            .into_response();
        let cookies = hydra.authorize_cookies.lock().unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            cookies[0].as_deref(),
            Some("ory_hydra_device_csrf=device-csrf; ory_kratos_session=session")
        );
    }

    /// The post-accept leg carries the gateway's public client id; it must be
    /// translated back to the Hydra client id before forwarding.
    #[tokio::test]
    async fn device_verify_replaces_client_id_with_ory_id() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([
            ("user_code".to_string(), "ABCD-EFGH".to_string()),
            ("client_id".to_string(), "gateway-client-1".to_string()),
        ]);
        let _ = device_verify(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let calls = hydra.authorize_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0]
                .iter()
                .find(|(k, _)| k == "client_id")
                .map(|(_, v)| v),
            Some(&"hydra-client-id-1".to_string())
        );
        assert!(
            calls[0]
                .iter()
                .any(|(k, v)| k == "user_code" && v == "ABCD-EFGH")
        );
    }

    #[tokio::test]
    async fn device_verify_returns_bad_gateway_on_hydra_error() {
        let state = Arc::new(err_state(Some("tenant-1".to_string())));
        let params = HashMap::from([("user_code".to_string(), "ABCD-EFGH".to_string())]);
        let resp = device_verify(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn token_succeeds_for_valid_client() {
        let state = Arc::new(ok_state(Some("tenant-1".to_string())));
        let form = HashMap::from([
            ("client_id".to_string(), "client-1".to_string()),
            ("client_secret".to_string(), "secret".to_string()),
        ]);
        let resp = token(State(state), HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn device_succeeds_for_valid_client() {
        let state = Arc::new(ok_state(Some("tenant-1".to_string())));
        let form = HashMap::from([
            ("client_id".to_string(), "client-1".to_string()),
            ("client_secret".to_string(), "secret".to_string()),
        ]);
        let resp = device(
            State(state),
            HeaderMap::new(),
            Path("auth".to_string()),
            Form(form),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    fn basic_auth_header(client_id: &str, secret: &str) -> HeaderValue {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{client_id}:{secret}"),
        );
        HeaderValue::from_str(&format!("Basic {encoded}")).unwrap()
    }

    #[tokio::test]
    async fn token_succeeds_with_basic_auth() {
        let state = Arc::new(ok_state(Some("tenant-1".to_string())));
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, basic_auth_header("client-1", "secret"));
        let form = HashMap::new();
        let resp = token(State(state), headers, Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn device_succeeds_with_basic_auth() {
        let state = Arc::new(ok_state(Some("tenant-1".to_string())));
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, basic_auth_header("client-1", "secret"));
        let form = HashMap::new();
        let resp = device(State(state), headers, Path("auth".to_string()), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    fn recording_state() -> (Arc<Oauth2State>, Arc<RecordingHydra>) {
        recording_state_with_response(json!({"status": "ok"}))
    }

    fn recording_state_with_response(
        response: serde_json::Value,
    ) -> (Arc<Oauth2State>, Arc<RecordingHydra>) {
        let hydra = Arc::new(RecordingHydra {
            response,
            ..Default::default()
        });
        let state = Arc::new(Oauth2State {
            hydra: hydra.clone(),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "tenant-1".to_string(),
                ))))),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "hydra-client-id-1".to_string(),
                ))))),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "gateway-public-1".to_string(),
                ))))),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        (state, hydra)
    }

    #[tokio::test]
    async fn authorize_replaces_client_id_with_ory_id() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([("client_id".to_string(), "gateway-client-1".to_string())]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let calls = hydra.authorize_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0]
                .iter()
                .find(|(k, _)| k == "client_id")
                .map(|(_, v)| v),
            Some(&"hydra-client-id-1".to_string())
        );
    }

    /// MSC2965: a Matrix-shaped authorize request gets `offline_access`
    /// appended before proxying so Hydra issues a refresh token.
    #[tokio::test]
    async fn authorize_appends_offline_access_for_matrix_scope() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            (
                "scope".to_string(),
                "openid urn:matrix:client:api:* urn:matrix:client:device:ABC".to_string(),
            ),
        ]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let calls = hydra.authorize_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].iter().find(|(k, _)| k == "scope").map(|(_, v)| v),
            Some(
                &"openid urn:matrix:client:api:* urn:matrix:client:device:ABC offline_access"
                    .to_string()
            )
        );
    }

    #[tokio::test]
    async fn authorize_leaves_matrix_scope_untouched_when_disabled() {
        let (state, hydra) = recording_state();
        let state = Arc::new(Oauth2State {
            matrix_offline_access_enabled: false,
            ..(*state).clone()
        });
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            (
                "scope".to_string(),
                "openid urn:matrix:client:api:*".to_string(),
            ),
        ]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let calls = hydra.authorize_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].iter().find(|(k, _)| k == "scope").map(|(_, v)| v),
            Some(&"openid urn:matrix:client:api:*".to_string())
        );
    }

    #[tokio::test]
    async fn authorize_leaves_non_matrix_scope_untouched() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            ("scope".to_string(), "openid profile".to_string()),
        ]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let calls = hydra.authorize_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].iter().find(|(k, _)| k == "scope").map(|(_, v)| v),
            Some(&"openid profile".to_string())
        );
    }

    #[tokio::test]
    async fn authorize_without_scope_stays_without_scope() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([("client_id".to_string(), "gateway-client-1".to_string())]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let calls = hydra.authorize_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].iter().all(|(k, _)| k != "scope"));
    }

    /// Guardrail: a Matrix-shaped authorize request may not smuggle
    /// non-OIDC/non-Matrix scopes (e.g. admin scopes) through the client's
    /// wildcard `*` registration.
    #[tokio::test]
    async fn authorize_rejects_admin_scope_alongside_matrix_scope() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            (
                "scope".to_string(),
                "openid urn:matrix:client:api:* tenant:admin".to_string(),
            ),
        ]);
        let resp = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["error"], "invalid_scope");
        assert!(value["error_description"]
            .as_str()
            .unwrap()
            .contains("tenant:admin"));
        assert!(
            hydra.authorize_calls.lock().unwrap().is_empty(),
            "rejected requests must not reach Hydra"
        );
    }

    /// The guardrail does not constrain non-Matrix authorize requests.
    #[tokio::test]
    async fn authorize_ignores_admin_scope_without_matrix_scope() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            ("scope".to_string(), "openid tenant:admin".to_string()),
        ]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let calls = hydra.authorize_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].iter().find(|(k, _)| k == "scope").map(|(_, v)| v),
            Some(&"openid tenant:admin".to_string())
        );
    }

    /// A fully valid Matrix scope set — including a per-login device scope
    /// and offline_access — passes the guardrail untouched.
    #[tokio::test]
    async fn authorize_passes_valid_matrix_scopes_with_device_and_offline_access() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            (
                "scope".to_string(),
                "openid urn:matrix:client:api:* urn:matrix:client:device:TESTDEV offline_access"
                    .to_string(),
            ),
        ]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let calls = hydra.authorize_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].iter().find(|(k, _)| k == "scope").map(|(_, v)| v),
            Some(
                &"openid urn:matrix:client:api:* urn:matrix:client:device:TESTDEV offline_access"
                    .to_string()
            )
        );
    }

    fn under_scoped_matrix_client() -> serde_json::Value {
        json!({
            "client_id": "hydra-client-id-1",
            "client_name": "element-web",
            "scope": "openid",
            "grant_types": ["authorization_code"],
        })
    }

    /// Self-heal: a client registered as plain `openid` (the real Element
    /// Web/Desktop DCR shape) is expanded to scope `*` and gains the
    /// refresh-token grant before the request is proxied.
    #[tokio::test]
    async fn authorize_expands_under_scoped_matrix_client() {
        let (state, hydra) = recording_state_with_response(under_scoped_matrix_client());
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            (
                "scope".to_string(),
                "openid urn:matrix:client:api:* urn:matrix:client:device:TESTDEV".to_string(),
            ),
        ]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let updates = hydra.update_calls.lock().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, "hydra-client-id-1");
        assert_eq!(updates[0].1["scope"], "*");
        // The update merges against the fetched client (Hydra PUT is
        // full-replacement): existing fields and grants are preserved.
        assert_eq!(updates[0].1["client_name"], "element-web");
        let grants: Vec<&str> = updates[0].1["grant_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(grants.contains(&"authorization_code"));
        assert!(grants.contains(&"refresh_token"));
        assert_eq!(hydra.authorize_calls.lock().unwrap().len(), 1);
    }

    /// A client whose registered scope already covers the request (wildcard)
    /// is not rewritten — no write on the hot path.
    #[tokio::test]
    async fn authorize_skips_expand_when_client_scope_covers() {
        let (state, hydra) = recording_state_with_response(json!({
            "client_id": "hydra-client-id-1",
            "scope": "*",
            "grant_types": ["authorization_code", "refresh_token"],
        }));
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            (
                "scope".to_string(),
                "openid urn:matrix:client:api:*".to_string(),
            ),
        ]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(hydra.get_client_calls.lock().unwrap().len(), 1);
        assert!(hydra.update_calls.lock().unwrap().is_empty());
        assert_eq!(hydra.authorize_calls.lock().unwrap().len(), 1);
    }

    /// A failing update never blocks the request: Hydra's own invalid_scope
    /// is the same failure the request had without the heal.
    #[tokio::test]
    async fn authorize_expand_failure_still_proxies() {
        let (state, hydra) = recording_state_with_response(under_scoped_matrix_client());
        let hydra = Arc::new(RecordingHydra {
            fail_update: true,
            ..(*hydra).clone()
        });
        let state = Arc::new(Oauth2State {
            hydra: hydra.clone(),
            ..(*state).clone()
        });
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            (
                "scope".to_string(),
                "openid urn:matrix:client:api:*".to_string(),
            ),
        ]);
        let resp = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(hydra.update_calls.lock().unwrap().len(), 1);
        assert_eq!(hydra.authorize_calls.lock().unwrap().len(), 1);
    }

    /// With offline access disabled the scope still expands to `*`, but the
    /// grant list is left untouched.
    #[tokio::test]
    async fn authorize_expand_omits_refresh_grant_when_offline_access_disabled() {
        let (state, hydra) = recording_state_with_response(under_scoped_matrix_client());
        let state = Arc::new(Oauth2State {
            matrix_offline_access_enabled: false,
            ..(*state).clone()
        });
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            (
                "scope".to_string(),
                "openid urn:matrix:client:api:*".to_string(),
            ),
        ]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        let updates = hydra.update_calls.lock().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].1["scope"], "*");
        assert_eq!(updates[0].1["grant_types"], json!(["authorization_code"]));
    }

    /// Non-Matrix authorize requests never fetch the client — the hot path
    /// is unchanged.
    #[tokio::test]
    async fn authorize_non_matrix_does_not_fetch_client() {
        let (state, hydra) = recording_state();
        let params = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            ("scope".to_string(), "openid profile".to_string()),
        ]);
        let _ = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert!(hydra.get_client_calls.lock().unwrap().is_empty());
        assert!(hydra.update_calls.lock().unwrap().is_empty());
        assert_eq!(hydra.authorize_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn token_replaces_form_client_id_with_ory_id() {
        let (state, hydra) = recording_state();
        let form = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            ("client_secret".to_string(), "secret".to_string()),
        ]);
        let _ = token(State(state), HeaderMap::new(), Form(form))
            .await
            .into_response();
        let calls = hydra.token_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (form, _) = &calls[0];
        assert_eq!(
            form.iter().find(|(k, _)| k == "client_id").map(|(_, v)| v),
            Some(&"hydra-client-id-1".to_string())
        );
    }

    #[tokio::test]
    async fn token_replaces_basic_auth_client_id_with_ory_id() {
        let (state, hydra) = recording_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            basic_auth_header("gateway-client-1", "secret"),
        );
        let form = HashMap::new();
        let _ = token(State(state), headers, Form(form))
            .await
            .into_response();
        let calls = hydra.token_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_, creds) = &calls[0];
        assert_eq!(
            creds.as_ref().map(|(id, _)| id.as_str()),
            Some("hydra-client-id-1")
        );
    }

    #[tokio::test]
    async fn device_replaces_client_id_with_ory_id() {
        let (state, hydra) = recording_state();
        let form = HashMap::from([
            ("client_id".to_string(), "gateway-client-1".to_string()),
            ("client_secret".to_string(), "secret".to_string()),
        ]);
        let _ = device(
            State(state),
            HeaderMap::new(),
            Path("auth".to_string()),
            Form(form),
        )
        .await
        .into_response();
        let calls = hydra.device_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_, form, _) = &calls[0];
        assert_eq!(
            form.iter().find(|(k, _)| k == "client_id").map(|(_, v)| v),
            Some(&"hydra-client-id-1".to_string())
        );
    }

    #[tokio::test]
    async fn userinfo_succeeds_with_token() {
        let state = Arc::new(ok_state(None));
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token-1"));
        let resp = userinfo(State(state), headers).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn userinfo_translates_sub_to_public_id() {
        let hydra = Arc::new(AlwaysOkHydra {
            response: json!({"sub": "kratos-identity-1", "email": "a@example.com"}),
        });
        let state = Arc::new(Oauth2State {
            hydra,
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(None)),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(None)),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "gateway-public-1".to_string(),
                ))))),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token-1"));
        let resp = userinfo(State(state), headers).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["sub"], "gateway-public-1");
        assert_eq!(value["email"], "a@example.com");
    }

    #[tokio::test]
    async fn userinfo_returns_unauthorized_without_token() {
        let state = Arc::new(ok_state(None));
        let resp = userinfo(State(state), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_succeeds() {
        let state = Arc::new(ok_state(None));
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = revoke(State(state), HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn revoke_clears_token_cache_when_configured() {
        let cache = Arc::new(MockTokenCache::default());
        let state = Arc::new(ok_state(None).with_token_cache(cache.clone()));
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = revoke(State(state), HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let removed = cache.removed.lock().unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], hash_token("token-1"));
    }

    #[tokio::test]
    async fn revoke_succeeds_when_cache_remove_fails() {
        let cache = Arc::new(MockTokenCache::with_remove_error());
        let state = Arc::new(ok_state(None).with_token_cache(cache.clone()));
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = revoke(State(state), HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let removed = cache.removed.lock().unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], hash_token("token-1"));
    }

    #[tokio::test]
    async fn openid_configuration_contains_expected_endpoints() {
        let state = Arc::new(test_state(None));
        let resp = openid_configuration(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["issuer"], "https://gateway.example.com");
        assert_eq!(
            value["authorization_endpoint"],
            "https://gateway.example.com/oauth2/auth"
        );
        assert_eq!(
            value["token_endpoint"],
            "https://gateway.example.com/oauth2/token"
        );
        assert_eq!(
            value["device_authorization_endpoint"],
            "https://gateway.example.com/oauth2/device/auth"
        );
        assert_eq!(
            value["userinfo_endpoint"],
            "https://gateway.example.com/oauth2/userinfo"
        );
        assert_eq!(
            value["jwks_uri"],
            "https://gateway.example.com/.well-known/jwks.json"
        );
        assert!(
            value["scopes_supported"]
                .as_array()
                .unwrap()
                .contains(&json!("openid"))
        );
        assert!(
            value["response_types_supported"]
                .as_array()
                .unwrap()
                .contains(&json!("code"))
        );
        assert_eq!(
            value["registration_endpoint"],
            "https://gateway.example.com/oauth2/register"
        );
        assert_eq!(
            value["introspection_endpoint"],
            "https://gateway.example.com/oauth2/introspect"
        );
        assert_eq!(
            value["code_challenge_methods_supported"],
            json!(["S256"])
        );
        assert!(
            value["token_endpoint_auth_methods_supported"]
                .as_array()
                .unwrap()
                .contains(&json!("none"))
        );
    }

    fn hydra_err() -> OryClientError {
        OryClientError::Ory {
            status: 500,
            message: "hydra error".into(),
        }
    }

    /// Hydra stub that always returns an OryClientError for every operation.
    #[derive(Clone, Default)]
    struct AlwaysErrHydra;

    #[async_trait]
    impl HydraOperations for AlwaysErrHydra {
        async fn authorize(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            Err(hydra_err())
        }

        async fn get_device_verify(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            Err(hydra_err())
        }

        async fn token(
            &self,
            _form: Vec<(String, String)>,
            _client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            Err(hydra_err())
        }

        async fn device(
            &self,
            _path: &str,
            _form: Vec<(String, String)>,
            _client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            Err(hydra_err())
        }

        async fn userinfo(&self, _token: &str) -> Result<serde_json::Value, OryClientError> {
            Err(hydra_err())
        }

        async fn introspect_token(
            &self,
            _token: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            Err(hydra_err())
        }

        async fn verify_client_credentials(
            &self,
            _client_id: &str,
            _client_secret: &str,
        ) -> Result<bool, OryClientError> {
            Err(hydra_err())
        }

        async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
            Err(hydra_err())
        }

        async fn create_oauth2_client(
            &self,
            _payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            Err(hydra_err())
        }

        async fn get_oauth2_client(
            &self,
            _id: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            Err(hydra_err())
        }

        async fn get_json(&self, _url: reqwest::Url) -> Result<serde_json::Value, OryClientError> {
            Err(hydra_err())
        }

        fn public_url(&self) -> &reqwest::Url {
            static URL: std::sync::OnceLock<reqwest::Url> = std::sync::OnceLock::new();
            URL.get_or_init(|| reqwest::Url::parse("http://127.0.0.1:4444").unwrap())
        }
    }

    fn err_state(tenant: Option<String>) -> Oauth2State {
        Oauth2State {
            hydra: Arc::new(AlwaysErrHydra),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(tenant.map(|t| Ok(Some(t))))),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "hydra-client-id-1".to_string(),
                ))))),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "gateway-public-1".to_string(),
                ))))),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        }
    }

    #[tokio::test]
    async fn jwks_returns_bad_gateway_on_hydra_error() {
        let state = Arc::new(err_state(None));
        let resp = jwks(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn authorize_returns_bad_gateway_on_hydra_error() {
        let state = Arc::new(err_state(Some("tenant-1".to_string())));
        let params = HashMap::from([("client_id".to_string(), "client-1".to_string())]);
        let resp = authorize(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn token_returns_bad_gateway_on_hydra_error() {
        let state = Arc::new(err_state(Some("tenant-1".to_string())));
        let form = HashMap::from([
            ("client_id".to_string(), "client-1".to_string()),
            ("client_secret".to_string(), "secret".to_string()),
        ]);
        let resp = token(State(state), HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn device_returns_bad_gateway_on_hydra_error() {
        let state = Arc::new(err_state(Some("tenant-1".to_string())));
        let form = HashMap::from([
            ("client_id".to_string(), "client-1".to_string()),
            ("client_secret".to_string(), "secret".to_string()),
        ]);
        let resp = device(
            State(state),
            HeaderMap::new(),
            Path("auth".to_string()),
            Form(form),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn userinfo_returns_bad_gateway_on_hydra_error() {
        let state = Arc::new(err_state(None));
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token-1"));
        let resp = userinfo(State(state), headers).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn revoke_returns_bad_gateway_on_hydra_error() {
        let state = Arc::new(err_state(None));
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = revoke(State(state), HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn hydra_client_as_hydra_operations_delegates() {
        let client = Arc::new(HydraClient::new("http://localhost:1", "http://localhost:1").unwrap())
            as Arc<dyn HydraOperations>;
        assert!(client.authorize(vec![], None).await.is_err());
        assert!(client.token(vec![], None).await.is_err());
        assert!(client.device("auth", vec![], None).await.is_err());
        assert!(client.userinfo("token").await.is_err());
        assert!(client.introspect_token("token").await.is_err());
        assert!(
            client
                .verify_client_credentials("id", "secret")
                .await
                .is_err()
        );
        assert!(client.get_oauth2_client("id").await.is_err());
        assert!(client.revoke(vec![]).await.is_err());
        assert!(
            client
                .create_oauth2_client(json!({"client_name": "test"}))
                .await
                .is_err()
        );
        assert!(
            client
                .get_json(reqwest::Url::parse("http://localhost:1").unwrap())
                .await
                .is_err()
        );
        assert_eq!(client.public_url().as_str(), "http://localhost:1/");
    }

    #[tokio::test]
    async fn stub_mapping_store_methods_are_callable() {
        let store = StubMappingStore {
            tenant_by_ory_id: Arc::new(std::sync::Mutex::new(None)),
            ory_by_public_id: Arc::new(std::sync::Mutex::new(Some(Ok(None)))),
            public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(None)))),
        };
        let _ = store.create("t", "hydra", "pub", "ory").await;
        let _ = store.get_ory_id("t", "hydra", "pub").await;
        let _ = store.get_ory_id_by_public_id("hydra", "pub").await;
        let _ = store.get_public_id("t", "hydra", "ory").await;
        let _ = store.get_public_id_by_ory_id("hydra", "ory").await;
        let _ = store.delete("t", "hydra", "pub").await;
        let _ = store.list_public_ids("t", "hydra").await;
    }

    #[tokio::test]
    async fn introspect_returns_forbidden_without_admin_scope() {
        let state = Arc::new(ok_state(None));
        let auth = AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "admin".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec!["openid".into()],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        };
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), Some(Extension(auth)), HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn introspect_includes_tenant_id_when_mapping_exists() {
        let hydra = Arc::new(AlwaysOkHydra {
            response: json!({
                "active": true,
                "sub": "hydra-client-id-1",
                "scope": "openid",
            }),
        });
        let state = Arc::new(Oauth2State {
            hydra,
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "tenant-1".to_string(),
                ))))),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(None)),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "gateway-public-1".to_string(),
                ))))),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        let auth = AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "admin".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec![SCOPE_TENANT_ADMIN.into()],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        };
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), Some(Extension(auth)), HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["active"], true);
        assert_eq!(value["tenant_id"], "tenant-1");
        assert_eq!(value["sub"], "gateway-public-1");
    }

    #[tokio::test]
    async fn introspect_returns_inactive_when_mapping_missing() {
        let hydra = Arc::new(AlwaysOkHydra {
            response: json!({
                "active": true,
                "sub": "hydra-client-id-1",
                "scope": "openid",
            }),
        });
        let state = Arc::new(Oauth2State {
            hydra,
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(None)))),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(None)),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(None)),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        let auth = AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "admin".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec![SCOPE_TENANT_ADMIN.into()],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        };
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), Some(Extension(auth)), HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["active"], false);
        assert!(value.get("tenant_id").is_none());
    }

    #[tokio::test]
    async fn introspect_translates_client_id_to_public_id() {
        let hydra = Arc::new(AlwaysOkHydra {
            response: json!({
                "active": true,
                "sub": "kratos-identity-1",
                "client_id": "hydra-client-id-1",
                "scope": "openid",
            }),
        });
        let state = Arc::new(Oauth2State {
            hydra,
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "tenant-1".to_string(),
                ))))),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(None)),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "gateway-public-1".to_string(),
                ))))),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        let auth = AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "admin".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec![SCOPE_TENANT_ADMIN.into()],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        };
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), Some(Extension(auth)), HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["active"], true);
        assert_eq!(value["sub"], "gateway-public-1");
        assert_eq!(value["client_id"], "gateway-public-1");
        assert_eq!(value["tenant_id"], "tenant-1");
    }

    #[tokio::test]
    async fn introspect_succeeds_with_client_basic_credentials() {
        let hydra = Arc::new(AlwaysOkHydra {
            response: json!({
                "active": true,
                "sub": "hydra-client-id-1",
                "scope": "openid",
            }),
        });
        let state = Arc::new(Oauth2State {
            hydra,
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "tenant-1".to_string(),
                ))))),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "hydra-client-id-1".to_string(),
                ))))),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "gateway-public-1".to_string(),
                ))))),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, basic_auth_header("gateway-client-1", "secret"));
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), None, headers, Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["active"], true);
        assert_eq!(value["tenant_id"], "tenant-1");
        assert_eq!(value["sub"], "gateway-public-1");
    }

    #[tokio::test]
    async fn introspect_rejects_wrong_client_secret() {
        let state = Arc::new(Oauth2State {
            hydra: Arc::new(AlwaysOkHydra {
                response: json!({"active": true, "sub": "hydra-client-id-1"}),
            }),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(None)),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "hydra-client-id-1".to_string(),
                ))))),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(None)),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            basic_auth_header("gateway-client-1", "wrong-secret"),
        );
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), None, headers, Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_to_string(resp).await;
        assert!(body.contains("invalid_client"));
    }

    #[tokio::test]
    async fn introspect_rejects_unknown_client_basic_credentials() {
        let state = Arc::new(resolve_state(Ok(None)));
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, basic_auth_header("unknown-client", "secret"));
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), None, headers, Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_to_string(resp).await;
        assert!(body.contains("invalid_client"));
    }

    #[tokio::test]
    async fn introspect_returns_unauthorized_without_any_credentials() {
        let state = Arc::new(ok_state(None));
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), None, HeaderMap::new(), Form(form))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[derive(Clone, Default)]
    struct StubKratos {
        result: Arc<std::sync::Mutex<Option<Result<serde_json::Value, OryClientError>>>>,
        calls: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl StubKratos {
        fn with_identity(identity: serde_json::Value) -> Self {
            Self {
                result: Arc::new(std::sync::Mutex::new(Some(Ok(identity)))),
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn failing() -> Self {
            Self {
                result: Arc::new(std::sync::Mutex::new(Some(Err(hydra_err())))),
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl IntrospectKratos for StubKratos {
        async fn get_identity(&self, id: &str) -> Result<serde_json::Value, OryClientError> {
            self.calls.lock().unwrap().push(id.to_string());
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(OryClientError::MissingTenant))
        }
    }

    fn introspect_email_state(
        hydra_response: serde_json::Value,
        kratos: StubKratos,
        force_ids: Vec<String>,
    ) -> Arc<Oauth2State> {
        Arc::new(Oauth2State {
            hydra: Arc::new(AlwaysOkHydra {
                response: hydra_response,
            }),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "tenant-1".to_string(),
                ))))),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(None)),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(Some(Ok(Some(
                    "gateway-public-1".to_string(),
                ))))),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: Some(Arc::new(kratos)),
            force_email_claim_client_ids: force_ids,
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        })
    }

    fn admin_auth() -> AuthContext {
        AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "admin".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec![SCOPE_TENANT_ADMIN.into()],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        }
    }

    async fn introspect_admin(state: Arc<Oauth2State>) -> serde_json::Value {
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(
            State(state),
            Some(Extension(admin_auth())),
            HeaderMap::new(),
            Form(form),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp).await;
        serde_json::from_str(&body).unwrap()
    }

    #[tokio::test]
    async fn introspect_injects_email_for_force_listed_raw_client_id() {
        let kratos = StubKratos::with_identity(json!({"traits": {"email": "m@example.com"}}));
        let calls = kratos.calls.clone();
        let state = introspect_email_state(
            json!({
                "active": true,
                "sub": "kratos-identity-1",
                "client_id": "hydra-client-id-1",
                "scope": "openid",
            }),
            kratos,
            vec!["hydra-client-id-1".to_string()],
        );
        let value = introspect_admin(state).await;
        assert_eq!(value["active"], true);
        assert_eq!(value["email"], "m@example.com");
        assert_eq!(*calls.lock().unwrap(), vec!["kratos-identity-1".to_string()]);
    }

    #[tokio::test]
    async fn introspect_injects_email_for_force_listed_public_client_id() {
        let kratos = StubKratos::with_identity(json!({"traits": {"email": "m@example.com"}}));
        let state = introspect_email_state(
            json!({
                "active": true,
                "sub": "kratos-identity-1",
                "client_id": "hydra-client-id-1",
                "scope": "openid",
            }),
            kratos,
            vec!["gateway-public-1".to_string()],
        );
        let value = introspect_admin(state).await;
        assert_eq!(value["email"], "m@example.com");
    }

    #[tokio::test]
    async fn introspect_injects_email_for_matrix_scope_without_config() {
        let kratos = StubKratos::with_identity(json!({"traits": {"email": "m@example.com"}}));
        let state = introspect_email_state(
            json!({
                "active": true,
                "sub": "kratos-identity-1",
                "client_id": "hydra-client-id-1",
                "scope": "openid urn:matrix:client:api:*",
            }),
            kratos,
            Vec::new(),
        );
        let value = introspect_admin(state).await;
        assert_eq!(value["email"], "m@example.com");
    }

    #[tokio::test]
    async fn introspect_skips_matrix_scope_email_when_flag_disabled() {
        let kratos = StubKratos::with_identity(json!({"traits": {"email": "m@example.com"}}));
        let calls = kratos.calls.clone();
        let state = introspect_email_state(
            json!({
                "active": true,
                "sub": "kratos-identity-1",
                "client_id": "hydra-client-id-1",
                "scope": "openid urn:matrix:client:api:*",
            }),
            kratos,
            Vec::new(),
        );
        let state = Arc::new(Oauth2State {
            matrix_email_claim_enabled: false,
            matrix_offline_access_enabled: true,
            ..(*state).clone()
        });
        let value = introspect_admin(state).await;
        assert_eq!(value["active"], true);
        assert!(value.get("email").is_none());
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn introspect_force_listed_client_injects_email_when_flag_disabled() {
        let kratos = StubKratos::with_identity(json!({"traits": {"email": "m@example.com"}}));
        let state = introspect_email_state(
            json!({
                "active": true,
                "sub": "kratos-identity-1",
                "client_id": "hydra-client-id-1",
                "scope": "openid",
            }),
            kratos,
            vec!["gateway-public-1".to_string()],
        );
        let state = Arc::new(Oauth2State {
            matrix_email_claim_enabled: false,
            matrix_offline_access_enabled: true,
            ..(*state).clone()
        });
        let value = introspect_admin(state).await;
        assert_eq!(value["email"], "m@example.com");
    }

    #[tokio::test]
    async fn introspect_skips_email_for_non_matching_token() {
        let kratos = StubKratos::with_identity(json!({"traits": {"email": "m@example.com"}}));
        let calls = kratos.calls.clone();
        let state = introspect_email_state(
            json!({
                "active": true,
                "sub": "kratos-identity-1",
                "client_id": "hydra-client-id-1",
                "scope": "openid profile",
            }),
            kratos,
            Vec::new(),
        );
        let value = introspect_admin(state).await;
        assert_eq!(value["active"], true);
        assert!(value.get("email").is_none());
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn introspect_returns_active_response_when_kratos_fails() {
        let state = introspect_email_state(
            json!({
                "active": true,
                "sub": "kratos-identity-1",
                "client_id": "hydra-client-id-1",
                "scope": "openid urn:matrix:client:api:*",
            }),
            StubKratos::failing(),
            Vec::new(),
        );
        let value = introspect_admin(state).await;
        assert_eq!(value["active"], true);
        assert_eq!(value["tenant_id"], "tenant-1");
        assert!(value.get("email").is_none());
    }

    #[tokio::test]
    async fn introspect_inactive_response_is_not_touched() {
        let kratos = StubKratos::with_identity(json!({"traits": {"email": "m@example.com"}}));
        let calls = kratos.calls.clone();
        let state = introspect_email_state(json!({"active": false}), kratos, Vec::new());
        let value = introspect_admin(state).await;
        assert_eq!(value, json!({"active": false}));
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cors_preflight_returns_204_with_headers() {
        let (state, _) = register_state();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::options("/oauth2/register")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let headers = resp.headers();
        assert_eq!(headers[axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(
            headers[axum::http::header::ACCESS_CONTROL_ALLOW_METHODS],
            "GET, POST, OPTIONS"
        );
        assert_eq!(
            headers[axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS],
            "authorization, content-type"
        );
        assert_eq!(headers[axum::http::header::ACCESS_CONTROL_MAX_AGE], "7200");
    }

    #[tokio::test]
    async fn cors_adds_allow_origin_to_regular_responses() {
        let (state, _) = register_state();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::get("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()[axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "*"
        );
    }

    #[derive(Clone, Default)]
    struct RecordingMappingStore {
        #[allow(clippy::type_complexity)]
        created: Arc<std::sync::Mutex<Vec<(String, String, String, String)>>>,
    }

    #[async_trait]
    impl IdMappingStore for RecordingMappingStore {
        async fn create(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
            ory_global_id: &str,
        ) -> Result<crate::db::IdMappingRow, crate::db::DbError> {
            self.created.lock().unwrap().push((
                tenant_id.to_string(),
                backend.to_string(),
                public_id.to_string(),
                ory_global_id.to_string(),
            ));
            Ok(crate::db::IdMappingRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                public_id: public_id.to_string(),
                ory_global_id: ory_global_id.to_string(),
                created_at: time::OffsetDateTime::now_utc(),
            })
        }

        async fn get_ory_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<String, crate::db::DbError> {
            unimplemented!()
        }

        async fn get_public_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, crate::db::DbError> {
            unimplemented!()
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<(), crate::db::DbError> {
            unimplemented!()
        }

        async fn list_public_ids(
            &self,
            _tenant_id: &str,
            _backend: &str,
        ) -> Result<Vec<String>, crate::db::DbError> {
            unimplemented!()
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, crate::db::DbError> {
            Ok(None)
        }
    }

    fn register_state() -> (Arc<Oauth2State>, Arc<RecordingMappingStore>) {
        let mappings = Arc::new(RecordingMappingStore::default());
        let state = Arc::new(Oauth2State {
            hydra: Arc::new(AlwaysOkHydra {
                response: json!({"status": "ok"}),
            }),
            mappings: mappings.clone(),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        (state, mappings)
    }

    fn register_recording_state() -> (
        Arc<Oauth2State>,
        Arc<RecordingHydra>,
        Arc<RecordingMappingStore>,
    ) {
        let hydra = Arc::new(RecordingHydra {
            response: json!({"status": "ok"}),
            ..Default::default()
        });
        let mappings = Arc::new(RecordingMappingStore::default());
        let state = Arc::new(Oauth2State {
            hydra: hydra.clone(),
            mappings: mappings.clone(),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        (state, hydra, mappings)
    }

    /// RFC 7591 registration is open: no credentials are required, and the
    /// client mapping is stored under the system tenant.
    #[tokio::test]
    async fn register_succeeds_without_credentials_and_maps_under_system_tenant() {
        let (state, mappings) = register_state();
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid profile",
            "token_endpoint_auth_method": "client_secret_basic",
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_str = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(value["client_id"].as_str().unwrap().starts_with("01"));
        assert_eq!(value["client_secret"], "ory-secret-1");
        assert_eq!(value["client_secret_expires_at"], 0);
        assert_eq!(value["scope"], "openid profile");

        let created = mappings.created.lock().unwrap();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].0, "system-tenant-1");
        assert_eq!(created[0].1, "hydra");
        assert_eq!(created[0].3, "ory-client-1");
    }

    /// An authenticated caller owns the new client under its own tenant
    /// instead of the system tenant (SSO-015).
    #[tokio::test]
    async fn register_maps_client_under_authenticated_tenant() {
        let (state, mappings) = register_state();
        let auth = AuthContext {
            tenant_id: "tenant-42".into(),
            subject: "admin".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec![],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        };
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
        });
        let resp = register(State(state), Some(Extension(auth)), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let created = mappings.created.lock().unwrap();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].0, "tenant-42");
    }

    /// When dynamic client registration is disabled the endpoint refuses
    /// with an OAuth2-style 403 instead of creating a client.
    #[tokio::test]
    async fn register_returns_forbidden_when_dcr_disabled() {
        let (state, mappings) = register_state();
        let state = Arc::new(Oauth2State {
            dynamic_client_registration_enabled: false,
            ..(*state).clone()
        });
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body_str = body_to_string(resp).await;
        assert!(body_str.contains("access_denied"));
        assert!(mappings.created.lock().unwrap().is_empty());
    }

    /// The discovery document only advertises the registration endpoint
    /// while dynamic client registration is enabled.
    #[tokio::test]
    async fn openid_configuration_omits_registration_endpoint_when_dcr_disabled() {
        let (state, _) = register_state();
        let state = Arc::new(Oauth2State {
            dynamic_client_registration_enabled: false,
            ..(*state).clone()
        });
        let resp = openid_configuration(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(value.get("registration_endpoint").is_none());
        assert_eq!(
            value["introspection_endpoint"],
            "https://gateway.example.com/oauth2/introspect"
        );
    }

    #[tokio::test]
    async fn register_returns_bad_request_for_invalid_redirect_uri() {
        let (state, _) = register_state();
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["not-a-url"],
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body_str = body_to_string(resp).await;
        assert!(body_str.contains("invalid_request"));
    }

    /// RFC 8252: public clients (token_endpoint_auth_method "none") may
    /// register custom-scheme redirect URIs (Element X Android uses
    /// io.element.android:/).
    #[tokio::test]
    async fn register_accepts_custom_scheme_redirect_for_public_client() {
        let (state, _) = register_state();
        let body = json!({
            "client_name": "element-x-android",
            "redirect_uris": ["io.element.android:/"],
            "token_endpoint_auth_method": "none",
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let value: serde_json::Value =
            serde_json::from_str(&body_to_string(resp).await).unwrap();
        assert_eq!(value["redirect_uris"][0], "io.element.android:/");
    }

    /// Custom schemes stay rejected for confidential clients, which play by
    /// the web rules.
    #[tokio::test]
    async fn register_rejects_custom_scheme_redirect_for_confidential_client() {
        let (state, _) = register_state();
        let body = json!({
            "client_name": "web-client",
            "redirect_uris": ["io.element.android:/"],
            "token_endpoint_auth_method": "client_secret_basic",
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body_str = body_to_string(resp).await;
        assert!(body_str.contains("invalid_request"));
    }

    /// Public registration enforces a scope ceiling: anything outside the
    /// plain OIDC surface is dropped.
    #[tokio::test]
    async fn register_drops_scopes_outside_the_dcr_ceiling() {
        let (state, _) = register_state();
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
            "scope": "openid tenant:admin email offline_access bogus:scope",
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_str = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(value["scope"], "openid email offline_access");
    }

    /// MSC2965: a Matrix-shaped registration is registered in Hydra with
    /// scope `*` — Hydra exact-matches scopes and per-login
    /// `urn:matrix:client:device:<id>` scopes can't be pre-registered — and
    /// the refresh-token grant is added. The response echoes the effective
    /// registered scope, as RFC 7591 expects. Non-Matrix scopes are still
    /// ceiling-filtered out of the shape check.
    #[tokio::test]
    async fn register_matrix_client_registers_wildcard_scope() {
        let (state, hydra, _) = register_recording_state();
        let body = json!({
            "client_name": "element-x-device",
            "redirect_uris": ["https://example.com/callback"],
            "scope": "openid urn:matrix:client:api:* tenant:admin",
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_str = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(value["scope"], "*");
        let grant_types: Vec<&str> = value["grant_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(grant_types.contains(&"authorization_code"));
        assert!(grant_types.contains(&"refresh_token"));
        let creates = hydra.create_calls.lock().unwrap();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0]["scope"], "*");
        let payload_grants: Vec<&str> = creates[0]["grant_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(payload_grants.contains(&"refresh_token"));
    }

    /// With the offline-access feature off, a Matrix registration still gets
    /// scope `*` (per-login device scopes can't be pre-registered either way)
    /// but no refresh-token grant.
    #[tokio::test]
    async fn register_matrix_client_without_offline_access_feature() {
        let (state, hydra, _) = register_recording_state();
        let state = Arc::new(Oauth2State {
            matrix_offline_access_enabled: false,
            ..(*state).clone()
        });
        let body = json!({
            "client_name": "element-x-device",
            "redirect_uris": ["https://example.com/callback"],
            "scope": "openid urn:matrix:client:api:*",
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_str = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(value["scope"], "*");
        assert_eq!(value["grant_types"], json!(["authorization_code"]));
        let creates = hydra.create_calls.lock().unwrap();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0]["scope"], "*");
        assert_eq!(creates[0]["grant_types"], json!(["authorization_code"]));
    }

    /// Non-Matrix registrations keep the enumerated scope ceiling; no
    /// wildcard is registered.
    #[tokio::test]
    async fn register_non_matrix_client_keeps_enumerated_scope() {
        let (state, hydra, _) = register_recording_state();
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
            "scope": "openid tenant:admin email",
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_str = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(value["scope"], "openid email");
        let creates = hydra.create_calls.lock().unwrap();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0]["scope"], "openid email");
    }

    #[tokio::test]
    async fn register_defaults_scope_to_openid_when_ceiling_empties_it() {
        let (state, _) = register_state();
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
            "scope": "tenant:admin",
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_str = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(value["scope"], "openid");
    }

    #[tokio::test]
    async fn register_returns_bad_gateway_on_hydra_error() {
        let state = Arc::new(Oauth2State {
            hydra: Arc::new(AlwaysErrHydra),
            mappings: Arc::new(RecordingMappingStore::default()),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn register_returns_bad_request_for_invalid_token_endpoint_auth_method() {
        let (state, _) = register_state();
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
            "token_endpoint_auth_method": "invalid_method",
        });
        let resp = register(State(state), None, Json(body)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body_str = body_to_string(resp).await;
        assert!(body_str.contains("invalid_request"));
    }

    #[derive(Clone, Default)]
    struct MissingClientIdHydra;

    #[async_trait]
    impl HydraOperations for MissingClientIdHydra {
        async fn authorize(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!()
        }
        async fn get_device_verify(
            &self,
            _query: Vec<(String, String)>,
            _cookie: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!()
        }
        async fn token(
            &self,
            _form: Vec<(String, String)>,
            _client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!()
        }
        async fn device(
            &self,
            _path: &str,
            _form: Vec<(String, String)>,
            _client_credentials: Option<(String, String)>,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!()
        }
        async fn userinfo(&self, _token: &str) -> Result<serde_json::Value, OryClientError> {
            unimplemented!()
        }
        async fn introspect_token(
            &self,
            _token: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!()
        }
        async fn verify_client_credentials(
            &self,
            _client_id: &str,
            _client_secret: &str,
        ) -> Result<bool, OryClientError> {
            unimplemented!()
        }
        async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
            unimplemented!()
        }
        async fn create_oauth2_client(
            &self,
            _payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(json!({"client_secret": "secret"}))
        }
        async fn get_oauth2_client(
            &self,
            _id: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!()
        }
        async fn get_json(&self, _url: reqwest::Url) -> Result<serde_json::Value, OryClientError> {
            unimplemented!()
        }
        fn public_url(&self) -> &reqwest::Url {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn register_returns_internal_error_when_hydra_response_missing_client_id() {
        let state = Arc::new(Oauth2State {
            hydra: Arc::new(MissingClientIdHydra),
            mappings: Arc::new(RecordingMappingStore::default()),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
        });
        let resp = register(State(state), None, Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[derive(Clone, Default)]
    struct FailingCreateMappingStore;

    #[async_trait]
    impl IdMappingStore for FailingCreateMappingStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
            _ory_global_id: &str,
        ) -> Result<crate::db::IdMappingRow, crate::db::DbError> {
            Err(crate::db::DbError::ConnectionNotFound)
        }

        async fn get_ory_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<String, crate::db::DbError> {
            unimplemented!()
        }

        async fn get_public_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, crate::db::DbError> {
            unimplemented!()
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<(), crate::db::DbError> {
            unimplemented!()
        }

        async fn list_public_ids(
            &self,
            _tenant_id: &str,
            _backend: &str,
        ) -> Result<Vec<String>, crate::db::DbError> {
            unimplemented!()
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, crate::db::DbError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn register_returns_internal_error_when_mapping_fails() {
        let state = Arc::new(Oauth2State {
            hydra: Arc::new(AlwaysOkHydra {
                response: json!({"status": "ok"}),
            }),
            mappings: Arc::new(FailingCreateMappingStore),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
        });
        let resp = register(State(state), None, Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn jwks_returns_bad_gateway_when_url_join_fails() {
        struct BadUrlHydra;
        #[async_trait]
        impl HydraOperations for BadUrlHydra {
            async fn authorize(
                &self,
                _query: Vec<(String, String)>,
                _cookie: Option<&str>,
            ) -> Result<serde_json::Value, OryClientError> {
                unimplemented!()
            }
            async fn get_device_verify(
                &self,
                _query: Vec<(String, String)>,
                _cookie: Option<&str>,
            ) -> Result<serde_json::Value, OryClientError> {
                unimplemented!()
            }
            async fn token(
                &self,
                _form: Vec<(String, String)>,
                _client_credentials: Option<(String, String)>,
            ) -> Result<serde_json::Value, OryClientError> {
                unimplemented!()
            }
            async fn device(
                &self,
                _path: &str,
                _form: Vec<(String, String)>,
                _client_credentials: Option<(String, String)>,
            ) -> Result<serde_json::Value, OryClientError> {
                unimplemented!()
            }
            async fn userinfo(&self, _token: &str) -> Result<serde_json::Value, OryClientError> {
                unimplemented!()
            }
            async fn introspect_token(
                &self,
                _token: &str,
            ) -> Result<serde_json::Value, OryClientError> {
                unimplemented!()
            }
            async fn verify_client_credentials(
                &self,
                _client_id: &str,
                _client_secret: &str,
            ) -> Result<bool, OryClientError> {
                unimplemented!()
            }
            async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
                unimplemented!()
            }
            async fn create_oauth2_client(
                &self,
                _payload: serde_json::Value,
            ) -> Result<serde_json::Value, OryClientError> {
                unimplemented!()
            }
            async fn get_oauth2_client(
                &self,
                _id: &str,
            ) -> Result<serde_json::Value, OryClientError> {
                unimplemented!()
            }
            async fn get_json(
                &self,
                _url: reqwest::Url,
            ) -> Result<serde_json::Value, OryClientError> {
                unimplemented!()
            }
            fn public_url(&self) -> &reqwest::Url {
                static URL: std::sync::OnceLock<reqwest::Url> = std::sync::OnceLock::new();
                URL.get_or_init(|| reqwest::Url::parse("data:text/html,hello").unwrap())
            }
        }
        let state = Arc::new(Oauth2State {
            hydra: Arc::new(BadUrlHydra),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(None)),
                ory_by_public_id: Arc::new(std::sync::Mutex::new(None)),
                public_id_by_ory_id: Arc::new(std::sync::Mutex::new(None)),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
            system_tenant_id: "system-tenant-1".to_string(),
            dynamic_client_registration_enabled: true,
            kratos: None,
            force_email_claim_client_ids: Vec::new(),
            matrix_email_claim_enabled: true,
            matrix_offline_access_enabled: true,
        });
        let resp = jwks(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
