use std::collections::HashMap;
use std::sync::Arc;

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

use crate::db::IdMappingRepo;

const BACKEND_HYDRA: &str = "hydra";
const TENANT_HEADER: &str = "x-tenant-id";

/// State shared by the OAuth2/OIDC HTTP handlers.
#[derive(Clone)]
pub struct Oauth2State {
    pub hydra: Arc<HydraClient>,
    pub mappings: IdMappingRepo,
    pub public_base_url: String,
}

pub fn router(state: Arc<Oauth2State>) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(openid_configuration))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth2/auth", get(authorize))
        .route("/oauth2/token", post(token))
        .route("/oauth2/userinfo", get(userinfo))
        .route("/oauth2/introspect", post(introspect))
        .route("/oauth2/revoke", post(revoke))
        .route(
            "/oauth2/auth/requests/login",
            get(get_login)
                .put(accept_login)
                .delete(reject_login),
        )
        .route(
            "/oauth2/auth/requests/consent",
            get(get_consent)
                .put(accept_consent)
                .delete(reject_consent),
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

async fn userinfo(
    State(state): State<Arc<Oauth2State>>,
    headers: HeaderMap,
) -> impl IntoResponse {
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

    #[test]
    fn base_url_trims_trailing_slash() {
        assert_eq!(base_url("https://example.com/"), "https://example.com");
        assert_eq!(base_url("https://example.com"), "https://example.com");
    }

    #[test]
    fn bearer_token_extracts_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret-token"));
        assert_eq!(bearer_token(&headers), Some("secret-token"));
    }

    #[test]
    fn bearer_token_rejects_non_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic dXNlcjpwYXNz"));
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
            resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
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

    async fn body_to_string(resp: Response<Body>) -> String {
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }
}
