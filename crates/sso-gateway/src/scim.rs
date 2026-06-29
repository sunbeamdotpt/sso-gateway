use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{Json, Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use sso_ory_client::hydra::HydraClient;
use tracing::warn;

use crate::{
    db::IdMappingRepo,
    proto::iam::v1::{ScimGroup, ScimUser},
    services::scim::ScimServiceImpl,
};

const BACKEND_HYDRA: &str = "hydra";
const SCIM_CONTENT_TYPE: &str = "application/scim+json";

/// A boxed SCIM error response keeps the `Result` error variant small.
#[derive(Debug)]
enum ScimError {
    Response(Box<Response<Body>>),
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response<Body> {
        match self {
            ScimError::Response(resp) => *resp,
        }
    }
}

impl From<connectrpc::ConnectError> for ScimError {
    fn from(err: connectrpc::ConnectError) -> Self {
        Self::Response(Box::new(map_service_error(err)))
    }
}

#[derive(Clone)]
pub struct ScimState {
    pub service: Arc<ScimServiceImpl>,
    pub hydra: Arc<HydraClient>,
    pub mappings: IdMappingRepo,
}

pub fn router(state: Arc<ScimState>) -> Router {
    Router::new()
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(resource_types))
        .route("/scim/v2/Schemas", get(schemas))
        .route("/scim/v2/Users", get(list_users).post(create_user))
        .route(
            "/scim/v2/Users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/scim/v2/Groups", get(list_groups).post(create_group))
        .route(
            "/scim/v2/Groups/{id}",
            get(get_group).put(update_group).delete(delete_group),
        )
        .with_state(state)
}

async fn resolve_tenant(state: &ScimState, headers: &HeaderMap) -> Result<String, ScimError> {
    let token = match bearer_token(headers) {
        Some(t) => t,
        None => {
            return Err(ScimError::Response(Box::new(scim_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
            ))));
        }
    };

    let introspect = state.hydra.introspect_token(token).await.map_err(|e| {
        warn!("token introspection failed: {}", e);
        ScimError::Response(Box::new(scim_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        )))
    })?;

    if !introspect["active"].as_bool().unwrap_or(false) {
        return Err(ScimError::Response(Box::new(scim_error(
            StatusCode::UNAUTHORIZED,
            "token inactive",
        ))));
    }

    let sub = introspect["sub"].as_str().ok_or_else(|| {
        ScimError::Response(Box::new(scim_error(
            StatusCode::UNAUTHORIZED,
            "missing subject",
        )))
    })?;

    let tenant_id = state
        .mappings
        .get_tenant_id_by_ory_id(BACKEND_HYDRA, sub)
        .await
        .map_err(|e| {
            warn!("tenant lookup failed for subject {}: {}", sub, e);
            ScimError::Response(Box::new(scim_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
            )))
        })?;

    match tenant_id {
        Some(t) => Ok(t),
        None => Err(ScimError::Response(Box::new(scim_error(
            StatusCode::UNAUTHORIZED,
            "unknown client",
        )))),
    }
}

async fn service_provider_config() -> impl IntoResponse {
    scim_json(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ServiceProviderConfig"],
        "documentationUri": "",
        "patch": { "supported": false },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": false, "maxResults": 0 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [
            { "name": "Bearer", "description": "OAuth bearer token", "specUri": "", "documentationUri": "", "type": "oauthbearertoken", "primary": true }
        ]
    }))
}

async fn resource_types() -> impl IntoResponse {
    scim_json(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": [
            { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User", "endpoint": "/Users", "schema": "urn:ietf:params:scim:schemas:core:2.0:User" },
            { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group" }
        ]
    }))
}

async fn schemas() -> impl IntoResponse {
    scim_json(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": [
            { "id": "urn:ietf:params:scim:schemas:core:2.0:User", "name": "User", "attributes": [] },
            { "id": "urn:ietf:params:scim:schemas:core:2.0:Group", "name": "Group", "attributes": [] }
        ]
    }))
}

async fn list_users(
    State(state): State<Arc<ScimState>>,
    headers: HeaderMap,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> Result<Response<Body>, ScimError> {
    let tenant_id = resolve_tenant(&state, &headers).await?;
    let resp = state.service.list_users_http(tenant_id).await?;
    let users: Vec<Value> = resp
        .body
        .users
        .into_iter()
        .map(|u| serde_json::to_value(u).unwrap_or_default())
        .collect();
    Ok(scim_json(list_response(users)))
}

async fn create_user(
    State(state): State<Arc<ScimState>>,
    headers: HeaderMap,
    Json(user): Json<ScimUser>,
) -> Result<Response<Body>, ScimError> {
    let tenant_id = resolve_tenant(&state, &headers).await?;
    let resp = state.service.create_user_http(tenant_id, user).await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn get_user(
    State(state): State<Arc<ScimState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response<Body>, ScimError> {
    let tenant_id = resolve_tenant(&state, &headers).await?;
    let resp = state.service.get_user_http(tenant_id, id).await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn update_user(
    State(state): State<Arc<ScimState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(user): Json<ScimUser>,
) -> Result<Response<Body>, ScimError> {
    let tenant_id = resolve_tenant(&state, &headers).await?;
    let resp = state.service.update_user_http(tenant_id, id, user).await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn delete_user(
    State(state): State<Arc<ScimState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response<Body>, ScimError> {
    let tenant_id = resolve_tenant(&state, &headers).await?;
    let _ = state.service.delete_user_http(tenant_id, id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn list_groups(
    State(state): State<Arc<ScimState>>,
    headers: HeaderMap,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> Result<Response<Body>, ScimError> {
    let tenant_id = resolve_tenant(&state, &headers).await?;
    let resp = state.service.list_groups_http(tenant_id).await?;
    let groups: Vec<Value> = resp
        .body
        .groups
        .into_iter()
        .map(|g| serde_json::to_value(g).unwrap_or_default())
        .collect();
    Ok(scim_json(list_response(groups)))
}

async fn create_group(
    State(state): State<Arc<ScimState>>,
    headers: HeaderMap,
    Json(group): Json<ScimGroup>,
) -> Result<Response<Body>, ScimError> {
    let tenant_id = resolve_tenant(&state, &headers).await?;
    let resp = state.service.create_group_http(tenant_id, group).await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn get_group(
    State(state): State<Arc<ScimState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response<Body>, ScimError> {
    let tenant_id = resolve_tenant(&state, &headers).await?;
    let resp = state.service.get_group_http(tenant_id, id).await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn update_group(
    State(state): State<Arc<ScimState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(group): Json<ScimGroup>,
) -> Result<Response<Body>, ScimError> {
    let tenant_id = resolve_tenant(&state, &headers).await?;
    let resp = state
        .service
        .update_group_http(tenant_id, id, group)
        .await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn delete_group(
    State(state): State<Arc<ScimState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response<Body>, ScimError> {
    let tenant_id = resolve_tenant(&state, &headers).await?;
    let _ = state.service.delete_group_http(tenant_id, id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
}

fn list_response(items: Vec<Value>) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": items.len(),
        "startIndex": 1,
        "itemsPerPage": items.len(),
        "Resources": items,
    })
}

fn scim_json(value: Value) -> Response<Body> {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, SCIM_CONTENT_TYPE)],
        axum::Json(value),
    )
        .into_response()
}

fn scim_error(status: StatusCode, detail: &str) -> Response<Body> {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, SCIM_CONTENT_TYPE)],
        axum::Json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": status.as_u16().to_string(),
            "detail": detail,
        })),
    )
        .into_response()
}

fn map_service_error(err: connectrpc::ConnectError) -> Response<Body> {
    let status = match err.code {
        connectrpc::ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
        connectrpc::ErrorCode::NotFound => StatusCode::NOT_FOUND,
        connectrpc::ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
        connectrpc::ErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
        connectrpc::ErrorCode::AlreadyExists => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    scim_error(status, &err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use http_body_util::BodyExt;

    #[test]
    fn bearer_token_extracts_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer scim-token"));
        assert_eq!(bearer_token(&headers), Some("scim-token"));
    }

    #[test]
    fn bearer_token_rejects_non_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn list_response_contains_items() {
        let resp = list_response(vec![json!({"id": "u1"}), json!({"id": "u2"})]);
        assert_eq!(resp["totalResults"], 2);
        assert_eq!(resp["Resources"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn scim_json_sets_content_type() {
        let resp = scim_json(json!({"ok": true}));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            SCIM_CONTENT_TYPE
        );
    }

    #[tokio::test]
    async fn scim_error_sets_status_and_detail() {
        let resp = scim_error(StatusCode::UNAUTHORIZED, "bad token");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("bad token"));
        assert!(body.contains("401"));
    }

    #[test]
    fn map_service_error_maps_codes() {
        for (code, expected) in [
            (
                connectrpc::ErrorCode::InvalidArgument,
                StatusCode::BAD_REQUEST,
            ),
            (connectrpc::ErrorCode::NotFound, StatusCode::NOT_FOUND),
            (
                connectrpc::ErrorCode::PermissionDenied,
                StatusCode::FORBIDDEN,
            ),
            (
                connectrpc::ErrorCode::Unauthenticated,
                StatusCode::UNAUTHORIZED,
            ),
            (connectrpc::ErrorCode::AlreadyExists, StatusCode::CONFLICT),
            (
                connectrpc::ErrorCode::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let err = connectrpc::ConnectError::new(code, "msg");
            assert_eq!(map_service_error(err).status(), expected);
        }
    }
}
