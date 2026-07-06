use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Extension, Form, Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use tracing::{instrument, warn};

use crate::auth::{
    AuthContext, SCOPE_APPLICATION_ADMIN, SCOPE_TENANT_ADMIN, hash_token,
    resolve_tenant_from_subject,
};
use crate::db::{IdMappingRepo, IdMappingStore, TokenIntrospectionCache};

const BACKEND_HYDRA: &str = "hydra";

/// Async trait for the Hydra operations used by the public OAuth2/OIDC handlers.
#[async_trait]
pub trait HydraOperations: Send + Sync + 'static {
    async fn authorize(
        &self,
        query: Vec<(String, String)>,
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
    async fn userinfo(&self, token: &str) -> Result<serde_json::Value, OryClientError>;
    async fn introspect_token(&self, token: &str) -> Result<serde_json::Value, OryClientError>;
    async fn revoke(&self, form: Vec<(String, String)>) -> Result<(), OryClientError>;
    async fn get_json(&self, url: reqwest::Url) -> Result<serde_json::Value, OryClientError>;
    fn public_url(&self) -> &reqwest::Url;
}

#[async_trait]
impl HydraOperations for HydraClient {
    async fn authorize(
        &self,
        query: Vec<(String, String)>,
    ) -> Result<serde_json::Value, OryClientError> {
        self.authorize(query).await
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

    async fn userinfo(&self, token: &str) -> Result<serde_json::Value, OryClientError> {
        self.userinfo(token).await
    }

    async fn introspect_token(&self, token: &str) -> Result<serde_json::Value, OryClientError> {
        self.introspect_token(token).await
    }

    async fn revoke(&self, form: Vec<(String, String)>) -> Result<(), OryClientError> {
        self.revoke(form).await
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
        .route("/oauth2/device/{*path}", post(device))
        .route("/oauth2/userinfo", get(userinfo))
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
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let client_id = params.get("client_id").cloned().unwrap_or_default();
    if let Err(err) = validate_public_client(&state, &client_id).await {
        return *err;
    }

    let query = params.into_iter().collect::<Vec<_>>();
    match state.hydra.authorize(query).await {
        Ok(value) => json_response(value),
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
    if let Err(err) = validate_public_client(&state, &client_id).await {
        return *err;
    }

    match state
        .hydra
        .token(form.into_iter().collect(), client_credentials)
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
    if let Err(err) = validate_public_client(&state, &client_id).await {
        return *err;
    }

    match state
        .hydra
        .device(&path, form.into_iter().collect(), client_credentials)
        .await
    {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn userinfo(State(state): State<Arc<Oauth2State>>, headers: HeaderMap) -> impl IntoResponse {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => return unauthorized(),
    };

    match state.hydra.userinfo(token).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn revoke(
    State(state): State<Arc<Oauth2State>>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = form.get("token").cloned();
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
        Some(sub) => sub,
        None => return json_response(value),
    };

    match resolve_tenant_from_subject(state.mappings.as_ref(), subject).await {
        Ok(tenant_id) => {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("tenant_id".to_string(), json!(tenant_id));
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

async fn validate_public_client(state: &Oauth2State, client_id: &str) -> Result<(), Box<Response>> {
    if client_id.is_empty() {
        return Err(Box::new(bad_request("missing client_id")));
    }

    let registered = state
        .mappings
        .get_tenant_id_by_ory_id(BACKEND_HYDRA, client_id)
        .await
        .map_err(|e| {
            warn!("failed to resolve tenant for client {}: {}", client_id, e);
            Box::new(internal_error())
        })?;

    if registered.is_none() {
        return Err(Box::new(
            (
                StatusCode::UNAUTHORIZED,
                json!({"error": "invalid_client"}).to_string(),
            )
                .into_response(),
        ));
    }

    Ok(())
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
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub authorize not configured")
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

        async fn get_json(&self, _url: reqwest::Url) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub get_json not configured")
        }

        fn public_url(&self) -> &reqwest::Url {
            unimplemented!("stub public_url not configured")
        }
    }

    #[derive(Clone, Default)]
    struct StubMappingStore {
        #[allow(clippy::type_complexity)]
        tenant_by_ory_id: Arc<std::sync::Mutex<Option<Result<Option<String>, crate::db::DbError>>>>,
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

        async fn get_public_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, crate::db::DbError> {
            Err(crate::db::DbError::ConnectionNotFound)
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
            Ok(())
        }
    }

    fn test_state(
        tenant_result: Option<Result<Option<String>, crate::db::DbError>>,
    ) -> Oauth2State {
        Oauth2State {
            hydra: Arc::new(StubHydra),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(tenant_result)),
            }),
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
    async fn validate_public_client_rejects_missing_client_id() {
        let state = test_state(None);
        let err = validate_public_client(&state, "").await.unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(*err).await;
        assert!(body.contains("missing client_id"));
    }

    #[tokio::test]
    async fn validate_public_client_rejects_unknown_client() {
        let state = test_state(Some(Ok(None)));
        let err = validate_public_client(&state, "unknown-client")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        let body = body_to_string(*err).await;
        assert!(body.contains("invalid_client"));
    }

    #[tokio::test]
    async fn validate_public_client_succeeds_for_registered_client() {
        let state = test_state(Some(Ok(Some("tenant-a".to_string()))));
        assert!(validate_public_client(&state, "client-1").await.is_ok());
    }

    #[tokio::test]
    async fn validate_public_client_maps_db_error_to_internal() {
        let state = test_state(Some(Err(crate::db::DbError::Sqlx(
            sqlx::Error::PoolTimedOut,
        ))));
        let err = validate_public_client(&state, "client-1")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn authorize_returns_bad_request_when_client_id_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = authorize(State(state), Query(params)).await.into_response();
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
        let resp = authorize(State(state), Query(params)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
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

    #[tokio::test]
    async fn userinfo_succeeds_with_token() {
        let state = Arc::new(ok_state(None));
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token-1"));
        let resp = userinfo(State(state), headers).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
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
        let resp = revoke(State(state), Form(form)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn revoke_clears_token_cache_when_configured() {
        let cache = Arc::new(MockTokenCache::default());
        let state = Arc::new(ok_state(None).with_token_cache(cache.clone()));
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = revoke(State(state), Form(form)).await.into_response();
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
        let resp = authorize(State(state), Query(params)).await.into_response();
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
        let resp = revoke(State(state), Form(form)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn hydra_client_as_hydra_operations_delegates() {
        let client = Arc::new(HydraClient::new("http://localhost:1", "http://localhost:1").unwrap())
            as Arc<dyn HydraOperations>;
        assert!(client.authorize(vec![]).await.is_err());
        assert!(client.token(vec![], None).await.is_err());
        assert!(client.device("auth", vec![], None).await.is_err());
        assert!(client.userinfo("token").await.is_err());
        assert!(client.revoke(vec![]).await.is_err());
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
        };
        let _ = store.create("t", "hydra", "pub", "ory").await;
        let _ = store.get_ory_id("t", "hydra", "pub").await;
        let _ = store.get_public_id("t", "hydra", "ory").await;
        let _ = store.delete("t", "hydra", "pub").await;
        let _ = store.list_public_ids("t", "hydra").await;
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
    async fn jwks_returns_bad_gateway_when_url_join_fails() {
        struct BadUrlHydra;
        #[async_trait]
        impl HydraOperations for BadUrlHydra {
            async fn authorize(
                &self,
                _query: Vec<(String, String)>,
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
            }),
            public_base_url: "https://gateway.example.com".to_string(),
            token_cache: None,
        });
        let resp = jwks(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
