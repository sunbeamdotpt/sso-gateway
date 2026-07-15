use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Extension, Form, Json, Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use tracing::{instrument, warn};
use ulid::Ulid;

use crate::auth::{
    AuthContext, SCOPE_APPLICATION_ADMIN, SCOPE_TENANT_ADMIN, hash_token,
    resolve_tenant_from_subject,
};
use crate::db::{IdMappingRepo, IdMappingStore, TokenIntrospectionCache};
use crate::services::application::{
    BACKEND_HYDRA, validate_redirect_uris, validate_token_endpoint_auth_method,
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
    async fn revoke(&self, form: Vec<(String, String)>) -> Result<(), OryClientError>;
    async fn create_oauth2_client(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;
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

    async fn revoke(&self, form: Vec<(String, String)>) -> Result<(), OryClientError> {
        self.revoke(form).await
    }

    async fn create_oauth2_client(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.create_oauth2_client(payload).await
    }

    async fn get_json(&self, url: reqwest::Url) -> Result<serde_json::Value, OryClientError> {
        self.get_json(url).await
    }

    fn public_url(&self) -> &reqwest::Url {
        self.public_url()
    }
}

/// State shared by the OAuth2/OIDC HTTP handlers.
#[derive(Clone)]
pub struct Oauth2State {
    pub(crate) hydra: Arc<dyn HydraOperations>,
    pub(crate) mappings: Arc<dyn IdMappingStore>,
    pub(crate) public_base_url: String,
    pub(crate) token_cache: Option<Arc<dyn TokenIntrospectionCache>>,
}

impl Oauth2State {
    pub fn new(hydra: Arc<HydraClient>, mappings: IdMappingRepo, public_base_url: String) -> Self {
        Self {
            hydra: hydra as Arc<dyn HydraOperations>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            public_base_url,
            token_cache: None,
        }
    }

    pub fn with_token_cache(mut self, cache: Arc<dyn TokenIntrospectionCache>) -> Self {
        self.token_cache = Some(cache);
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
        .with_state(state)
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
    let body = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth2/auth"),
        "token_endpoint": format!("{base}/oauth2/token"),
        "device_authorization_endpoint": format!("{base}/oauth2/device/auth"),
        "userinfo_endpoint": format!("{base}/oauth2/userinfo"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "revocation_endpoint": format!("{base}/oauth2/revoke"),
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "grant_types_supported": ["authorization_code", "implicit", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
    });
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
        Err(err) => return map_ory_error(err),
    };

    match state.hydra.get_json(url).await {
        Ok(keys) => json_response(keys),
        Err(err) => map_ory_error(err),
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
    let client_id = params.get("client_id").cloned().unwrap_or_default();
    let ory_id = match resolve_public_client_for_authorize(&state, &client_id).await {
        Ok(id) => id,
        Err(err) => return *err,
    };

    let query = params
        .into_iter()
        .map(|(k, v)| {
            if k == "client_id" {
                (k, ory_id.clone())
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
        Err(err) => map_ory_error(err),
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
        Err(err) => map_ory_error(err),
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
        Err(err) => map_ory_error(err),
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
        Err(err) => map_ory_error(err),
    }
}

async fn userinfo(State(state): State<Arc<Oauth2State>>, headers: HeaderMap) -> impl IntoResponse {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => return unauthorized(),
    };

    let mut value = match state.hydra.userinfo(token).await {
        Ok(value) => value,
        Err(err) => return map_ory_error(err),
    };

    if let Some(obj) = value.as_object_mut()
        && let Some(sub) = obj.get("sub").and_then(|v| v.as_str())
        && let Some(public_id) = translate_ory_id_to_public_id(&state, sub).await
    {
        obj.insert("sub".to_string(), json!(public_id));
    }

    json_response(value)
}

async fn register(
    State(state): State<Arc<Oauth2State>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !auth.scopes.iter().any(|s| s == SCOPE_APPLICATION_ADMIN) {
        return forbidden();
    }

    let redirect_uris = json_string_array(&body["redirect_uris"]);
    let grant_types = json_string_array(&body["grant_types"]);
    let response_types = json_string_array(&body["response_types"]);
    let scope = body["scope"]
        .as_str()
        .map(|s| {
            s.split_whitespace()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let token_endpoint_auth_method = body["token_endpoint_auth_method"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if let Err(err) = validate_redirect_uris(&redirect_uris, false) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "invalid_request", "error_description": err.to_string()})),
        )
            .into_response();
    }
    if let Err(err) = validate_token_endpoint_auth_method(&token_endpoint_auth_method) {
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
        "grant_types": if grant_types.is_empty() { vec!["authorization_code".to_string()] } else { grant_types.clone() },
        "response_types": if response_types.is_empty() { vec!["code".to_string()] } else { response_types.clone() },
        "scope": scope.join(" "),
        "token_endpoint_auth_method": token_endpoint_auth_method,
    });

    let created = match state.hydra.create_oauth2_client(payload).await {
        Ok(value) => value,
        Err(err) => return map_ory_error(err),
    };

    let ory_id = match created["client_id"].as_str() {
        Some(id) => id,
        None => return internal_error(),
    };
    let client_secret = created["client_secret"].as_str().unwrap_or("").to_string();

    match state
        .mappings
        .create(&auth.tenant_id, BACKEND_HYDRA, &public_id, ory_id)
        .await
    {
        Ok(_) => {}
        Err(err) => {
            warn!(
                tenant_id = %auth.tenant_id,
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
        "scope": scope.join(" "),
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
        Err(err) => map_ory_error(err),
    }
}

async fn introspect(
    State(state): State<Arc<Oauth2State>>,
    Extension(auth): Extension<AuthContext>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if !auth
        .scopes
        .iter()
        .any(|s| s == SCOPE_TENANT_ADMIN || s == SCOPE_APPLICATION_ADMIN)
    {
        return forbidden();
    }

    let token = match form.get("token") {
        Some(t) => t,
        None => return bad_request("missing token"),
    };

    let mut value = match state.hydra.introspect_token(token).await {
        Ok(value) => value,
        Err(err) => return map_ory_error(err),
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

async fn resolve_public_client(
    state: &Oauth2State,
    client_id: &str,
) -> Result<String, Box<Response>> {
    if client_id.is_empty() {
        return Err(Box::new(bad_request("missing client_id")));
    }

    state
        .mappings
        .get_ory_id_by_public_id(BACKEND_HYDRA, client_id)
        .await
        .map_err(|e| {
            warn!("failed to resolve public client {}: {}", client_id, e);
            match e {
                crate::db::DbError::MappingNotFound => Box::new(
                    (
                        StatusCode::UNAUTHORIZED,
                        json!({"error": "invalid_client"}).to_string(),
                    )
                        .into_response(),
                ),
                _ => Box::new(internal_error()),
            }
        })
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

#[instrument(skip(err))]
fn map_ory_error(err: OryClientError) -> Response<Body> {
    let status = match &err {
        OryClientError::Ory { status, .. } => match status {
            400 => StatusCode::BAD_REQUEST,
            401 => StatusCode::UNAUTHORIZED,
            403 => StatusCode::FORBIDDEN,
            404 => StatusCode::NOT_FOUND,
            _ => StatusCode::BAD_GATEWAY,
        },
        OryClientError::Http(_) | OryClientError::Url(_) => StatusCode::BAD_GATEWAY,
        OryClientError::Serialization(_) | OryClientError::InvalidResponse(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        OryClientError::MissingTenant => StatusCode::UNAUTHORIZED,
        OryClientError::Redirect { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    };
    warn!(?err, "ory backend error");
    let body = json!({"error": "server_error"});
    (status, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

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

        async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
            unimplemented!("stub revoke not configured")
        }

        async fn create_oauth2_client(
            &self,
            _payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub create_oauth2_client not configured")
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
        }
    }

    fn resolve_state(ory_result: Result<Option<String>, crate::db::DbError>) -> Oauth2State {
        Oauth2State {
            hydra: Arc::new(StubHydra),
            mappings: Arc::new(StubMappingStore::with_ory_by_public_id(ory_result)),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
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
        let resp = map_ory_error(OryClientError::MissingTenant);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = map_ory_error(OryClientError::InvalidResponse("fail".into()));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let resp = map_ory_error(OryClientError::Ory {
            status: 400,
            message: "bad".into(),
        });
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = map_ory_error(OryClientError::Ory {
            status: 401,
            message: "unauth".into(),
        });
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = map_ory_error(OryClientError::Ory {
            status: 403,
            message: "forbidden".into(),
        });
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp = map_ory_error(OryClientError::Ory {
            status: 404,
            message: "not found".into(),
        });
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp = map_ory_error(OryClientError::Ory {
            status: 500,
            message: "down".into(),
        });
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let resp = map_ory_error(OryClientError::Serialization(
            serde_json::from_str::<serde_json::Value>("not json").unwrap_err(),
        ));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn map_ory_error_http_and_url_variants() {
        let resp = map_ory_error(OryClientError::Http(
            reqwest::get("http://localhost:1").await.unwrap_err(),
        ));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let resp = map_ory_error(OryClientError::Url(
            reqwest::Url::parse("not-a-url").unwrap_err(),
        ));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn map_ory_error_body_is_generic() {
        let resp = map_ory_error(OryClientError::Ory {
            status: 500,
            message: "sensitive details".into(),
        });
        let body = body_to_string(resp).await;
        assert!(body.contains("server_error"));
        assert!(!body.contains("sensitive details"));
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
        let resp = map_ory_error(OryClientError::Ory {
            status: 409,
            message: "conflict".into(),
        });
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn map_ory_error_maps_unknown_ory_status_to_bad_gateway() {
        let resp = map_ory_error(OryClientError::Ory {
            status: 503,
            message: "unavailable".into(),
        });
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

        async fn revoke(&self, form: Vec<(String, String)>) -> Result<(), OryClientError> {
            self.inner.revoke(form).await
        }

        async fn create_oauth2_client(
            &self,
            payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            self.inner.create_oauth2_client(payload).await
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
        let hydra = Arc::new(RecordingHydra {
            response: json!({"status": "ok"}),
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
        assert!(value.get("introspection_endpoint").is_none());
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

        async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
            Err(hydra_err())
        }

        async fn create_oauth2_client(
            &self,
            _payload: serde_json::Value,
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
            scopes: vec!["openid".into()],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        };
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), Extension(auth), Form(form))
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
        });
        let auth = AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "admin".into(),
            scopes: vec![SCOPE_TENANT_ADMIN.into()],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        };
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), Extension(auth), Form(form))
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
        });
        let auth = AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "admin".into(),
            scopes: vec![SCOPE_TENANT_ADMIN.into()],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        };
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), Extension(auth), Form(form))
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
        });
        let auth = AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "admin".into(),
            scopes: vec![SCOPE_TENANT_ADMIN.into()],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        };
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), Extension(auth), Form(form))
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

    fn register_state() -> Arc<Oauth2State> {
        Arc::new(Oauth2State {
            hydra: Arc::new(AlwaysOkHydra {
                response: json!({"status": "ok"}),
            }),
            mappings: Arc::new(RecordingMappingStore::default()),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
        })
    }

    fn register_auth(scopes: Vec<String>) -> AuthContext {
        AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "admin".into(),
            scopes,
            token_hash: "hash".into(),
            authentication_methods: vec![],
        }
    }

    #[tokio::test]
    async fn register_returns_forbidden_without_application_admin_scope() {
        let state = register_state();
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
        });
        let resp = register(
            State(state),
            Extension(register_auth(vec!["tenant:read".into()])),
            Json(body),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn register_returns_bad_request_for_invalid_redirect_uri() {
        let state = register_state();
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["not-a-url"],
        });
        let resp = register(
            State(state),
            Extension(register_auth(vec![SCOPE_APPLICATION_ADMIN.into()])),
            Json(body),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body_str = body_to_string(resp).await;
        assert!(body_str.contains("invalid_request"));
    }

    #[tokio::test]
    async fn register_creates_client_and_mapping() {
        let state = register_state();
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid profile",
            "token_endpoint_auth_method": "client_secret_basic",
        });
        let resp = register(
            State(state.clone()),
            Extension(register_auth(vec![SCOPE_APPLICATION_ADMIN.into()])),
            Json(body),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_str = body_to_string(resp).await;
        let value: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(value["client_id"].as_str().unwrap().starts_with("01"));
        assert_eq!(value["client_secret"], "ory-secret-1");
        assert_eq!(value["client_secret_expires_at"], 0);
        assert_eq!(value["scope"], "openid profile");
    }

    #[tokio::test]
    async fn register_returns_bad_gateway_on_hydra_error() {
        let state = Arc::new(Oauth2State {
            hydra: Arc::new(AlwaysErrHydra),
            mappings: Arc::new(RecordingMappingStore::default()),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
        });
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
        });
        let resp = register(
            State(state),
            Extension(register_auth(vec![SCOPE_APPLICATION_ADMIN.into()])),
            Json(body),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn register_returns_bad_request_for_invalid_token_endpoint_auth_method() {
        let state = register_state();
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
            "token_endpoint_auth_method": "invalid_method",
        });
        let resp = register(
            State(state),
            Extension(register_auth(vec![SCOPE_APPLICATION_ADMIN.into()])),
            Json(body),
        )
        .await
        .into_response();
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
        async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
            unimplemented!()
        }
        async fn create_oauth2_client(
            &self,
            _payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(json!({"client_secret": "secret"}))
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
        });
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
        });
        let resp = register(
            State(state),
            Extension(register_auth(vec![SCOPE_APPLICATION_ADMIN.into()])),
            Json(body),
        )
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
        });
        let body = json!({
            "client_name": "test-client",
            "redirect_uris": ["https://example.com/callback"],
        });
        let resp = register(
            State(state),
            Extension(register_auth(vec![SCOPE_APPLICATION_ADMIN.into()])),
            Json(body),
        )
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
            async fn revoke(&self, _form: Vec<(String, String)>) -> Result<(), OryClientError> {
                unimplemented!()
            }
            async fn create_oauth2_client(
                &self,
                _payload: serde_json::Value,
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
        });
        let resp = jwks(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
