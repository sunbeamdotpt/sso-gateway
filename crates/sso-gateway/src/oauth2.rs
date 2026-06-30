use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use tracing::warn;

use crate::db::{IdMappingRepo, IdMappingStore};

const BACKEND_HYDRA: &str = "hydra";
const TENANT_HEADER: &str = "x-tenant-id";

/// Async trait for the Hydra operations used by the public OAuth2/OIDC handlers.
#[async_trait]
pub trait HydraOperations: Send + Sync + 'static {
    async fn authorize(
        &self,
        query: Vec<(String, String)>,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn token(&self, form: Vec<(String, String)>) -> Result<serde_json::Value, OryClientError>;
    async fn userinfo(&self, token: &str) -> Result<serde_json::Value, OryClientError>;
    async fn introspect_token(&self, token: &str) -> Result<serde_json::Value, OryClientError>;
    async fn revoke(&self, form: Vec<(String, String)>) -> Result<(), OryClientError>;
    async fn get_login_request(&self, challenge: &str) -> Result<serde_json::Value, OryClientError>;
    async fn accept_login_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn reject_login_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn get_consent_request(&self, challenge: &str)
        -> Result<serde_json::Value, OryClientError>;
    async fn accept_consent_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn reject_consent_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn get_logout_request(&self, challenge: &str)
        -> Result<serde_json::Value, OryClientError>;
    async fn accept_logout_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;
    async fn reject_logout_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;
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
    ) -> Result<serde_json::Value, OryClientError> {
        self.token(form).await
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

    async fn get_login_request(&self, challenge: &str) -> Result<serde_json::Value, OryClientError> {
        self.get_login_request(challenge).await
    }

    async fn accept_login_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.accept_login_request(challenge, body).await
    }

    async fn reject_login_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.reject_login_request(challenge, body).await
    }

    async fn get_consent_request(
        &self,
        challenge: &str,
    ) -> Result<serde_json::Value, OryClientError> {
        self.get_consent_request(challenge).await
    }

    async fn accept_consent_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.accept_consent_request(challenge, body).await
    }

    async fn reject_consent_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.reject_consent_request(challenge, body).await
    }

    async fn get_logout_request(
        &self,
        challenge: &str,
    ) -> Result<serde_json::Value, OryClientError> {
        self.get_logout_request(challenge).await
    }

    async fn accept_logout_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.accept_logout_request(challenge, body).await
    }

    async fn reject_logout_request(
        &self,
        challenge: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.reject_logout_request(challenge, body).await
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
}

impl Oauth2State {
    pub fn new(hydra: Arc<HydraClient>, mappings: IdMappingRepo, public_base_url: String) -> Self {
        Self {
            hydra: hydra as Arc<dyn HydraOperations>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            public_base_url,
        }
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
        .route("/oauth2/userinfo", get(userinfo))
        .route("/oauth2/introspect", post(introspect))
        .route("/oauth2/revoke", post(revoke))
        .route(
            "/oauth2/auth/requests/login",
            get(get_login).put(accept_login).delete(reject_login),
        )
        .route(
            "/oauth2/auth/requests/consent",
            get(get_consent).put(accept_consent).delete(reject_consent),
        )
        .route(
            "/oauth2/auth/requests/logout",
            get(get_logout).put(accept_logout).delete(reject_logout),
        )
        .with_state(state)
}

fn base_url(public_base_url: &str) -> String {
    public_base_url.trim_end_matches('/').to_string()
}

async fn openid_configuration(State(state): State<Arc<Oauth2State>>) -> impl IntoResponse {
    let base = base_url(&state.public_base_url);
    let body = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth2/auth"),
        "token_endpoint": format!("{base}/oauth2/token"),
        "userinfo_endpoint": format!("{base}/oauth2/userinfo"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "introspection_endpoint": format!("{base}/oauth2/introspect"),
        "revocation_endpoint": format!("{base}/oauth2/revoke"),
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "grant_types_supported": ["authorization_code", "implicit", "client_credentials", "refresh_token"],
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
    let client_id = params.get("client_id").cloned().unwrap_or_default();
    if let Err(err) = validate_public_client(&state, &headers, &client_id).await {
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
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let client_id = form.get("client_id").cloned().unwrap_or_default();
    if let Err(err) = validate_public_client(&state, &headers, &client_id).await {
        return *err;
    }

    match state.hydra.token(form.into_iter().collect()).await {
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

async fn introspect(
    State(state): State<Arc<Oauth2State>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    if let Err(err) = require_tenant_header(&headers) {
        return *err;
    }

    let token = match form.get("token") {
        Some(t) => t.clone(),
        None => return bad_request("missing token"),
    };

    match state.hydra.introspect_token(&token).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn revoke(
    State(state): State<Arc<Oauth2State>>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    match state.hydra.revoke(form.into_iter().collect()).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => map_ory_error(err),
    }
}

async fn get_login(
    State(state): State<Arc<Oauth2State>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let challenge = match params.get("login_challenge") {
        Some(c) => c.clone(),
        None => return bad_request("missing login_challenge"),
    };
    match state.hydra.get_login_request(&challenge).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn accept_login(
    State(state): State<Arc<Oauth2State>>,
    Query(params): Query<HashMap<String, String>>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    let challenge = match params.get("login_challenge") {
        Some(c) => c.clone(),
        None => return bad_request("missing login_challenge"),
    };
    match state.hydra.accept_login_request(&challenge, body).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn reject_login(
    State(state): State<Arc<Oauth2State>>,
    Query(params): Query<HashMap<String, String>>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    let challenge = match params.get("login_challenge") {
        Some(c) => c.clone(),
        None => return bad_request("missing login_challenge"),
    };
    match state.hydra.reject_login_request(&challenge, body).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn get_consent(
    State(state): State<Arc<Oauth2State>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let challenge = match params.get("consent_challenge") {
        Some(c) => c.clone(),
        None => return bad_request("missing consent_challenge"),
    };
    match state.hydra.get_consent_request(&challenge).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn accept_consent(
    State(state): State<Arc<Oauth2State>>,
    Query(params): Query<HashMap<String, String>>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    let challenge = match params.get("consent_challenge") {
        Some(c) => c.clone(),
        None => return bad_request("missing consent_challenge"),
    };
    match state.hydra.accept_consent_request(&challenge, body).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn reject_consent(
    State(state): State<Arc<Oauth2State>>,
    Query(params): Query<HashMap<String, String>>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    let challenge = match params.get("consent_challenge") {
        Some(c) => c.clone(),
        None => return bad_request("missing consent_challenge"),
    };
    match state.hydra.reject_consent_request(&challenge, body).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn get_logout(
    State(state): State<Arc<Oauth2State>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let challenge = match params.get("logout_challenge") {
        Some(c) => c.clone(),
        None => return bad_request("missing logout_challenge"),
    };
    match state.hydra.get_logout_request(&challenge).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn accept_logout(
    State(state): State<Arc<Oauth2State>>,
    Query(params): Query<HashMap<String, String>>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    let challenge = match params.get("logout_challenge") {
        Some(c) => c.clone(),
        None => return bad_request("missing logout_challenge"),
    };
    match state.hydra.accept_logout_request(&challenge, body).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn reject_logout(
    State(state): State<Arc<Oauth2State>>,
    Query(params): Query<HashMap<String, String>>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    let challenge = match params.get("logout_challenge") {
        Some(c) => c.clone(),
        None => return bad_request("missing logout_challenge"),
    };
    match state.hydra.reject_logout_request(&challenge, body).await {
        Ok(value) => json_response(value),
        Err(err) => map_ory_error(err),
    }
}

async fn validate_public_client(
    state: &Oauth2State,
    headers: &HeaderMap,
    client_id: &str,
) -> Result<(), Box<Response>> {
    if client_id.is_empty() {
        return Err(Box::new(bad_request("missing client_id")));
    }

    let expected_tenant = state
        .mappings
        .get_tenant_id_by_ory_id(BACKEND_HYDRA, client_id)
        .await
        .map_err(|e| {
            warn!("failed to resolve tenant for client {}: {}", client_id, e);
            Box::new(internal_error())
        })?;

    let expected_tenant = match expected_tenant {
        Some(t) => t,
        None => {
            return Err(Box::new(
                (
                    StatusCode::UNAUTHORIZED,
                    json!({"error": "invalid_client"}).to_string(),
                )
                    .into_response(),
            ));
        }
    };

    if let Some(header_tenant) = headers.get(TENANT_HEADER).and_then(|h| h.to_str().ok())
        && header_tenant != expected_tenant
    {
        return Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                json!({"error": "tenant_mismatch"}).to_string(),
            )
                .into_response(),
        ));
    }

    Ok(())
}

fn require_tenant_header(headers: &HeaderMap) -> Result<(), Box<Response>> {
    if headers.get(TENANT_HEADER).is_none() {
        return Err(Box::new(unauthorized()));
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

fn internal_error() -> Response<Body> {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({"error": "server_error"})),
    )
        .into_response()
}

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
    let body = json!({"error": "server_error", "message": err.to_string()});
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
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub token not configured")
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

        async fn get_login_request(
            &self,
            _challenge: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub get_login_request not configured")
        }

        async fn accept_login_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub accept_login_request not configured")
        }

        async fn reject_login_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub reject_login_request not configured")
        }

        async fn get_consent_request(
            &self,
            _challenge: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub get_consent_request not configured")
        }

        async fn accept_consent_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub accept_consent_request not configured")
        }

        async fn reject_consent_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub reject_consent_request not configured")
        }

        async fn get_logout_request(
            &self,
            _challenge: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub get_logout_request not configured")
        }

        async fn accept_logout_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub accept_logout_request not configured")
        }

        async fn reject_logout_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            unimplemented!("stub reject_logout_request not configured")
        }

        async fn get_json(
            &self,
            _url: reqwest::Url,
        ) -> Result<serde_json::Value, OryClientError> {
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
            unimplemented!()
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
            self.tenant_by_ory_id.lock().unwrap().take().expect("stub not configured")
        }
    }

    fn test_state(tenant_result: Option<Result<Option<String>, crate::db::DbError>>) -> Oauth2State {
        Oauth2State {
            hydra: Arc::new(StubHydra),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(tenant_result)),
            }),
            public_base_url: "https://gateway.example.com".to_string(),
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
    fn require_tenant_header_succeeds_when_present() {
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_HEADER, HeaderValue::from_static("tenant-1"));
        assert!(require_tenant_header(&headers).is_ok());
    }

    #[test]
    fn require_tenant_header_fails_when_missing() {
        let headers = HeaderMap::new();
        let err = require_tenant_header(&headers).unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
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
        assert_eq!(
            base_url("https://example.com///"),
            "https://example.com"
        );
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
    fn require_tenant_header_succeeds_with_non_utf8_value() {
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_HEADER, HeaderValue::from_bytes(b"\xff").unwrap());
        assert!(require_tenant_header(&headers).is_ok());
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
    async fn map_ory_error_body_contains_message() {
        let resp = map_ory_error(OryClientError::Ory {
            status: 500,
            message: "hydra down".into(),
        });
        let body = body_to_string(resp).await;
        assert!(body.contains("hydra down"));
    }

    #[tokio::test]
    async fn validate_public_client_rejects_missing_client_id() {
        let state = test_state(None);
        let headers = HeaderMap::new();
        let err = validate_public_client(&state, &headers, "").await.unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(*err).await;
        assert!(body.contains("missing client_id"));
    }

    #[tokio::test]
    async fn validate_public_client_rejects_unknown_client() {
        let state = test_state(Some(Ok(None)));
        let headers = HeaderMap::new();
        let err = validate_public_client(&state, &headers, "unknown-client")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        let body = body_to_string(*err).await;
        assert!(body.contains("invalid_client"));
    }

    #[tokio::test]
    async fn validate_public_client_rejects_tenant_mismatch() {
        let state = test_state(Some(Ok(Some("tenant-a".to_string()))));
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_HEADER, HeaderValue::from_static("tenant-b"));
        let err = validate_public_client(&state, &headers, "client-1")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
        let body = body_to_string(*err).await;
        assert!(body.contains("tenant_mismatch"));
    }

    #[tokio::test]
    async fn validate_public_client_succeeds_when_tenant_matches() {
        let state = test_state(Some(Ok(Some("tenant-a".to_string()))));
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_HEADER, HeaderValue::from_static("tenant-a"));
        assert!(validate_public_client(&state, &headers, "client-1").await.is_ok());
    }

    #[tokio::test]
    async fn validate_public_client_succeeds_without_tenant_header() {
        let state = test_state(Some(Ok(Some("tenant-a".to_string()))));
        let headers = HeaderMap::new();
        assert!(validate_public_client(&state, &headers, "client-1").await.is_ok());
    }

    #[tokio::test]
    async fn validate_public_client_maps_db_error_to_internal() {
        let state = test_state(Some(Err(crate::db::DbError::Sqlx(sqlx::Error::PoolTimedOut))));
        let headers = HeaderMap::new();
        let err = validate_public_client(&state, &headers, "client-1")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn authorize_returns_bad_request_when_client_id_missing() {
        let state = Arc::new(test_state(None));
        let headers = HeaderMap::new();
        let params = HashMap::new();
        let resp = authorize(State(state), headers, Query(params)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing client_id"));
    }

    #[tokio::test]
    async fn get_login_returns_bad_request_when_challenge_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = get_login(State(state), Query(params)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing login_challenge"));
    }

    #[tokio::test]
    async fn accept_login_returns_bad_request_when_challenge_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = accept_login(State(state), Query(params), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing login_challenge"));
    }

    #[tokio::test]
    async fn reject_login_returns_bad_request_when_challenge_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = reject_login(State(state), Query(params), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing login_challenge"));
    }

    #[tokio::test]
    async fn get_consent_returns_bad_request_when_challenge_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = get_consent(State(state), Query(params)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing consent_challenge"));
    }

    #[tokio::test]
    async fn accept_consent_returns_bad_request_when_challenge_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = accept_consent(State(state), Query(params), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing consent_challenge"));
    }

    #[tokio::test]
    async fn reject_consent_returns_bad_request_when_challenge_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = reject_consent(State(state), Query(params), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing consent_challenge"));
    }

    #[tokio::test]
    async fn get_logout_returns_bad_request_when_challenge_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = get_logout(State(state), Query(params)).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing logout_challenge"));
    }

    #[tokio::test]
    async fn accept_logout_returns_bad_request_when_challenge_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = accept_logout(State(state), Query(params), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing logout_challenge"));
    }

    #[tokio::test]
    async fn reject_logout_returns_bad_request_when_challenge_missing() {
        let state = Arc::new(test_state(None));
        let params = HashMap::new();
        let resp = reject_logout(State(state), Query(params), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing logout_challenge"));
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
            value["userinfo_endpoint"],
            "https://gateway.example.com/oauth2/userinfo"
        );
        assert_eq!(
            value["jwks_uri"],
            "https://gateway.example.com/.well-known/jwks.json"
        );
        assert!(value["scopes_supported"].as_array().unwrap().contains(&json!("openid")));
        assert!(value["response_types_supported"].as_array().unwrap().contains(&json!("code")));
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

        async fn get_login_request(
            &self,
            _challenge: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn accept_login_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn reject_login_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn get_consent_request(
            &self,
            _challenge: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn accept_consent_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn reject_consent_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn get_logout_request(
            &self,
            _challenge: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn accept_logout_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn reject_logout_request(
            &self,
            _challenge: &str,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            Ok(self.response.clone())
        }

        async fn get_json(
            &self,
            _url: reqwest::Url,
        ) -> Result<serde_json::Value, OryClientError> {
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
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_HEADER, HeaderValue::from_static("tenant-1"));
        let params = HashMap::from([("client_id".to_string(), "client-1".to_string())]);
        let resp = authorize(State(state), headers, Query(params)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn token_succeeds_for_valid_client() {
        let state = Arc::new(ok_state(Some("tenant-1".to_string())));
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_HEADER, HeaderValue::from_static("tenant-1"));
        let form = HashMap::from([("client_id".to_string(), "client-1".to_string())]);
        let resp = token(State(state), headers, Form(form)).await.into_response();
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
        let resp = userinfo(State(state), HeaderMap::new()).await.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn introspect_succeeds_with_token_and_tenant() {
        let state = Arc::new(ok_state(None));
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_HEADER, HeaderValue::from_static("tenant-1"));
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = introspect(State(state), headers, Form(form)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn introspect_returns_bad_request_without_token() {
        let state = Arc::new(ok_state(None));
        let mut headers = HeaderMap::new();
        headers.insert(TENANT_HEADER, HeaderValue::from_static("tenant-1"));
        let resp = introspect(State(state), headers, Form(HashMap::new())).await.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn revoke_succeeds() {
        let state = Arc::new(ok_state(None));
        let form = HashMap::from([("token".to_string(), "token-1".to_string())]);
        let resp = revoke(State(state), Form(form)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn login_request_lifecycle_succeeds() {
        let state = Arc::new(ok_state(None));
        let params = HashMap::from([("login_challenge".to_string(), "ch-1".to_string())]);
        let resp = get_login(State(state.clone()), Query(params.clone())).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = accept_login(State(state.clone()), Query(params.clone()), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = reject_login(State(state), Query(params), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn consent_request_lifecycle_succeeds() {
        let state = Arc::new(ok_state(None));
        let params = HashMap::from([("consent_challenge".to_string(), "ch-1".to_string())]);
        let resp = get_consent(State(state.clone()), Query(params.clone())).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = accept_consent(State(state.clone()), Query(params.clone()), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = reject_consent(State(state), Query(params), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logout_request_lifecycle_succeeds() {
        let state = Arc::new(ok_state(None));
        let params = HashMap::from([("logout_challenge".to_string(), "ch-1".to_string())]);
        let resp = get_logout(State(state.clone()), Query(params.clone())).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = accept_logout(State(state.clone()), Query(params.clone()), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = reject_logout(State(state), Query(params), axum::extract::Json(json!({})))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
