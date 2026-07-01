use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Json, Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use tracing::warn;

use crate::{
    db::{IdMappingRepo, IdMappingStore},
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

/// Async trait for the Hydra operations used by the SCIM HTTP handlers.
#[async_trait]
pub trait ScimHydra: Send + Sync + 'static {
    async fn introspect_token(&self, token: &str) -> Result<Value, OryClientError>;
}

#[async_trait]
impl ScimHydra for HydraClient {
    async fn introspect_token(&self, token: &str) -> Result<Value, OryClientError> {
        self.introspect_token(token).await
    }
}

/// Async trait for the SCIM service operations used by the HTTP handlers.
#[async_trait]
pub trait ScimServiceOps: Send + Sync + 'static {
    async fn list_users_http(
        &self,
        tenant_id: String,
    ) -> Result<connectrpc::Response<crate::proto::iam::v1::ScimListUsersResponse>, connectrpc::ConnectError>;
    async fn create_user_http(
        &self,
        tenant_id: String,
        user: ScimUser,
    ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError>;
    async fn get_user_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError>;
    async fn update_user_http(
        &self,
        tenant_id: String,
        id: String,
        user: ScimUser,
    ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError>;
    async fn delete_user_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<connectrpc::Response<buffa_types::google::protobuf::Empty>, connectrpc::ConnectError>;
    async fn list_groups_http(
        &self,
        tenant_id: String,
    ) -> Result<connectrpc::Response<crate::proto::iam::v1::ScimListGroupsResponse>, connectrpc::ConnectError>;
    async fn create_group_http(
        &self,
        tenant_id: String,
        group: ScimGroup,
    ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError>;
    async fn get_group_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError>;
    async fn update_group_http(
        &self,
        tenant_id: String,
        id: String,
        group: ScimGroup,
    ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError>;
    async fn delete_group_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<connectrpc::Response<buffa_types::google::protobuf::Empty>, connectrpc::ConnectError>;
}

#[async_trait]
impl ScimServiceOps for ScimServiceImpl {
    async fn list_users_http(
        &self,
        tenant_id: String,
    ) -> Result<connectrpc::Response<crate::proto::iam::v1::ScimListUsersResponse>, connectrpc::ConnectError>
    {
        self.list_users_http(tenant_id).await
    }

    async fn create_user_http(
        &self,
        tenant_id: String,
        user: ScimUser,
    ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
        self.create_user_http(tenant_id, user).await
    }

    async fn get_user_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
        self.get_user_http(tenant_id, id).await
    }

    async fn update_user_http(
        &self,
        tenant_id: String,
        id: String,
        user: ScimUser,
    ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
        self.update_user_http(tenant_id, id, user).await
    }

    async fn delete_user_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<connectrpc::Response<buffa_types::google::protobuf::Empty>, connectrpc::ConnectError>
    {
        self.delete_user_http(tenant_id, id).await
    }

    async fn list_groups_http(
        &self,
        tenant_id: String,
    ) -> Result<connectrpc::Response<crate::proto::iam::v1::ScimListGroupsResponse>, connectrpc::ConnectError>
    {
        self.list_groups_http(tenant_id).await
    }

    async fn create_group_http(
        &self,
        tenant_id: String,
        group: ScimGroup,
    ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
        self.create_group_http(tenant_id, group).await
    }

    async fn get_group_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
        self.get_group_http(tenant_id, id).await
    }

    async fn update_group_http(
        &self,
        tenant_id: String,
        id: String,
        group: ScimGroup,
    ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
        self.update_group_http(tenant_id, id, group).await
    }

    async fn delete_group_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<connectrpc::Response<buffa_types::google::protobuf::Empty>, connectrpc::ConnectError>
    {
        self.delete_group_http(tenant_id, id).await
    }
}

#[derive(Clone)]
pub struct ScimState {
    pub(crate) service: Arc<dyn ScimServiceOps>,
    pub(crate) hydra: Arc<dyn ScimHydra>,
    pub(crate) mappings: Arc<dyn IdMappingStore>,
}

impl ScimState {
    pub fn new(service: Arc<ScimServiceImpl>, hydra: Arc<HydraClient>, mappings: IdMappingRepo) -> Self {
        Self {
            service: service as Arc<dyn ScimServiceOps>,
            hydra: hydra as Arc<dyn ScimHydra>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
        }
    }
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
    use std::sync::Mutex;

    use axum::extract::Request;

    #[derive(Clone, Default)]
    struct StubHydra {
        introspect_result: Arc<std::sync::Mutex<Option<Result<Value, OryClientError>>>>,
    }

    #[async_trait]
    impl ScimHydra for StubHydra {
        async fn introspect_token(&self, _token: &str) -> Result<Value, OryClientError> {
            self.introspect_result.lock().unwrap().take().expect("stub not configured")
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

    fn test_state(
        hydra_result: Option<Result<Value, OryClientError>>,
        mapping_result: Option<Result<Option<String>, crate::db::DbError>>,
    ) -> ScimState {
        #[derive(Default)]
        struct NoOpService;

        #[async_trait]
        impl ScimServiceOps for NoOpService {
            async fn list_users_http(
                &self,
                _tenant_id: String,
            ) -> Result<connectrpc::Response<crate::proto::iam::v1::ScimListUsersResponse>, connectrpc::ConnectError>
            {
                unimplemented!()
            }
            async fn create_user_http(
                &self,
                _tenant_id: String,
                _user: ScimUser,
            ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
                unimplemented!()
            }
            async fn get_user_http(
                &self,
                _tenant_id: String,
                _id: String,
            ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
                unimplemented!()
            }
            async fn update_user_http(
                &self,
                _tenant_id: String,
                _id: String,
                _user: ScimUser,
            ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
                unimplemented!()
            }
            async fn delete_user_http(
                &self,
                _tenant_id: String,
                _id: String,
            ) -> Result<connectrpc::Response<buffa_types::google::protobuf::Empty>, connectrpc::ConnectError>
            {
                unimplemented!()
            }
            async fn list_groups_http(
                &self,
                _tenant_id: String,
            ) -> Result<connectrpc::Response<crate::proto::iam::v1::ScimListGroupsResponse>, connectrpc::ConnectError>
            {
                unimplemented!()
            }
            async fn create_group_http(
                &self,
                _tenant_id: String,
                _group: ScimGroup,
            ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
                unimplemented!()
            }
            async fn get_group_http(
                &self,
                _tenant_id: String,
                _id: String,
            ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
                unimplemented!()
            }
            async fn update_group_http(
                &self,
                _tenant_id: String,
                _id: String,
                _group: ScimGroup,
            ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
                unimplemented!()
            }
            async fn delete_group_http(
                &self,
                _tenant_id: String,
                _id: String,
            ) -> Result<connectrpc::Response<buffa_types::google::protobuf::Empty>, connectrpc::ConnectError>
            {
                unimplemented!()
            }
        }

        ScimState {
            service: Arc::new(NoOpService),
            hydra: Arc::new(StubHydra {
                introspect_result: Arc::new(std::sync::Mutex::new(hydra_result)),
            }),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(std::sync::Mutex::new(mapping_result)),
            }),
        }
    }

    fn error_status(err: &ScimError) -> StatusCode {
        match err {
            ScimError::Response(resp) => resp.status(),
        }
    }

    async fn body_to_json(resp: Response<Body>) -> Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

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

    #[tokio::test]
    async fn service_provider_config_returns_expected_schema() {
        let resp = service_provider_config().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            SCIM_CONTENT_TYPE
        );
        let body = body_to_json(resp).await;
        assert_eq!(
            body["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:ServiceProviderConfig"
        );
        assert_eq!(body["patch"]["supported"], false);
    }

    #[tokio::test]
    async fn resource_types_returns_user_and_group() {
        let resp = resource_types().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_json(resp).await;
        assert_eq!(body["totalResults"], 2);
        let resources = body["Resources"].as_array().unwrap();
        assert!(resources.iter().any(|r| r["id"] == "User"));
        assert!(resources.iter().any(|r| r["id"] == "Group"));
    }

    #[tokio::test]
    async fn schemas_returns_user_and_group_schemas() {
        let resp = schemas().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_json(resp).await;
        assert_eq!(body["totalResults"], 2);
        let resources = body["Resources"].as_array().unwrap();
        assert!(resources.iter().any(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:User"));
        assert!(resources.iter().any(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:Group"));
    }

    #[tokio::test]
    async fn resolve_tenant_rejects_missing_authorization() {
        let state = test_state(None, None);
        let headers = HeaderMap::new();
        let err = resolve_tenant(&state, &headers).await.unwrap_err();
        assert_eq!(error_status(&err), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn resolve_tenant_rejects_inactive_token() {
        let state = test_state(
            Some(Ok(json!({"active": false}))),
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        let err = resolve_tenant(&state, &headers).await.unwrap_err();
        assert_eq!(error_status(&err), StatusCode::UNAUTHORIZED);
        let body = body_to_json(err.into_response()).await;
        assert!(body["detail"].as_str().unwrap().contains("inactive"));
    }

    #[tokio::test]
    async fn resolve_tenant_rejects_missing_subject() {
        let state = test_state(
            Some(Ok(json!({"active": true}))),
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        let err = resolve_tenant(&state, &headers).await.unwrap_err();
        assert_eq!(error_status(&err), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn resolve_tenant_rejects_unknown_client() {
        let state = test_state(
            Some(Ok(json!({"active": true, "sub": "sub-1"}))),
            Some(Ok(None)),
        );
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        let err = resolve_tenant(&state, &headers).await.unwrap_err();
        assert_eq!(error_status(&err), StatusCode::UNAUTHORIZED);
        let body = body_to_json(err.into_response()).await;
        assert!(body["detail"].as_str().unwrap().contains("unknown client"));
    }

    #[tokio::test]
    async fn resolve_tenant_maps_db_error_to_internal() {
        let state = test_state(
            Some(Ok(json!({"active": true, "sub": "sub-1"}))),
            Some(Err(crate::db::DbError::Sqlx(sqlx::Error::PoolTimedOut))),
        );
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        let err = resolve_tenant(&state, &headers).await.unwrap_err();
        assert_eq!(error_status(&err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn resolve_tenant_succeeds_for_active_known_token() {
        let state = test_state(
            Some(Ok(json!({"active": true, "sub": "sub-1"}))),
            Some(Ok(Some("tenant-1".to_string()))),
        );
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        let tenant = resolve_tenant(&state, &headers).await.unwrap();
        assert_eq!(tenant, "tenant-1");
    }

    #[derive(Clone, Default)]
    struct StubService {
        list_users: Arc<Mutex<Option<Result<connectrpc::Response<crate::proto::iam::v1::ScimListUsersResponse>, connectrpc::ConnectError>>>>,
        create_user: Arc<Mutex<Option<Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError>>>>,
        get_user: Arc<Mutex<Option<Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError>>>>,
        update_user: Arc<Mutex<Option<Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError>>>>,
        delete_user: Arc<Mutex<Option<Result<connectrpc::Response<buffa_types::google::protobuf::Empty>, connectrpc::ConnectError>>>>,
        list_groups: Arc<Mutex<Option<Result<connectrpc::Response<crate::proto::iam::v1::ScimListGroupsResponse>, connectrpc::ConnectError>>>>,
        create_group: Arc<Mutex<Option<Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError>>>>,
        get_group: Arc<Mutex<Option<Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError>>>>,
        update_group: Arc<Mutex<Option<Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError>>>>,
        delete_group: Arc<Mutex<Option<Result<connectrpc::Response<buffa_types::google::protobuf::Empty>, connectrpc::ConnectError>>>>,
    }

    #[async_trait]
    impl ScimServiceOps for StubService {
        async fn list_users_http(
            &self,
            _tenant_id: String,
        ) -> Result<connectrpc::Response<crate::proto::iam::v1::ScimListUsersResponse>, connectrpc::ConnectError> {
            self.list_users.lock().unwrap().take().expect("list_users stub not configured")
        }
        async fn create_user_http(
            &self,
            _tenant_id: String,
            _user: ScimUser,
        ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
            self.create_user.lock().unwrap().take().expect("create_user stub not configured")
        }
        async fn get_user_http(
            &self,
            _tenant_id: String,
            _id: String,
        ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
            self.get_user.lock().unwrap().take().expect("get_user stub not configured")
        }
        async fn update_user_http(
            &self,
            _tenant_id: String,
            _id: String,
            _user: ScimUser,
        ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
            self.update_user.lock().unwrap().take().expect("update_user stub not configured")
        }
        async fn delete_user_http(
            &self,
            _tenant_id: String,
            _id: String,
        ) -> Result<connectrpc::Response<buffa_types::google::protobuf::Empty>, connectrpc::ConnectError> {
            self.delete_user.lock().unwrap().take().expect("delete_user stub not configured")
        }
        async fn list_groups_http(
            &self,
            _tenant_id: String,
        ) -> Result<connectrpc::Response<crate::proto::iam::v1::ScimListGroupsResponse>, connectrpc::ConnectError> {
            self.list_groups.lock().unwrap().take().expect("list_groups stub not configured")
        }
        async fn create_group_http(
            &self,
            _tenant_id: String,
            _group: ScimGroup,
        ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
            self.create_group.lock().unwrap().take().expect("create_group stub not configured")
        }
        async fn get_group_http(
            &self,
            _tenant_id: String,
            _id: String,
        ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
            self.get_group.lock().unwrap().take().expect("get_group stub not configured")
        }
        async fn update_group_http(
            &self,
            _tenant_id: String,
            _id: String,
            _group: ScimGroup,
        ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
            self.update_group.lock().unwrap().take().expect("update_group stub not configured")
        }
        async fn delete_group_http(
            &self,
            _tenant_id: String,
            _id: String,
        ) -> Result<connectrpc::Response<buffa_types::google::protobuf::Empty>, connectrpc::ConnectError> {
            self.delete_group.lock().unwrap().take().expect("delete_group stub not configured")
        }
    }

    fn route_state_with_service(service: Arc<dyn ScimServiceOps>) -> Arc<ScimState> {
        Arc::new(ScimState {
            service,
            hydra: Arc::new(StubHydra {
                introspect_result: Arc::new(Mutex::new(Some(Ok(json!({"active": true, "sub": "sub-1"}))))),
            }),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(Mutex::new(Some(Ok(Some("tenant-1".to_string()))))),
            }),
        })
    }

    fn authenticated_request(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, "Bearer token");
        match body {
            Some(value) => {
                builder = builder.header(axum::http::header::CONTENT_TYPE, "application/json");
                builder.body(Body::from(value.to_string())).unwrap()
            }
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    async fn call(router: &mut axum::Router, req: Request<Body>) -> Response<Body> {
        use tower::ServiceExt;
        router.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn router_exposes_service_provider_config() {
        let state = route_state_with_service(Arc::new(StubService::default()));
        let mut router = router(state);
        let req = authenticated_request("GET", "/scim/v2/ServiceProviderConfig", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_exposes_resource_types() {
        let state = route_state_with_service(Arc::new(StubService::default()));
        let mut router = router(state);
        let req = authenticated_request("GET", "/scim/v2/ResourceTypes", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_exposes_schemas() {
        let state = route_state_with_service(Arc::new(StubService::default()));
        let mut router = router(state);
        let req = authenticated_request("GET", "/scim/v2/Schemas", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_users_route_returns_users() {
        let service = Arc::new(StubService {
            list_users: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(
                crate::proto::iam::v1::ScimListUsersResponse {
                    users: vec![ScimUser {
                        user_name: "alice".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("GET", "/scim/v2/Users", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_json(resp).await;
        assert_eq!(body["totalResults"], 1);
    }

    #[tokio::test]
    async fn create_user_route_returns_user() {
        let service = Arc::new(StubService {
            create_user: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(ScimUser {
                user_name: "alice".into(),
                ..Default::default()
            }))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("POST", "/scim/v2/Users", Some(json!({"userName": "alice"})));
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_json(resp).await;
        assert_eq!(body["userName"], "alice");
    }

    #[tokio::test]
    async fn get_user_route_returns_user() {
        let service = Arc::new(StubService {
            get_user: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(ScimUser {
                id: "u1".into(),
                user_name: "alice".into(),
                ..Default::default()
            }))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("GET", "/scim/v2/Users/u1", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_json(resp).await;
        assert_eq!(body["id"], "u1");
    }

    #[tokio::test]
    async fn update_user_route_returns_user() {
        let service = Arc::new(StubService {
            update_user: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(ScimUser {
                id: "u1".into(),
                user_name: "alison".into(),
                ..Default::default()
            }))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("PUT", "/scim/v2/Users/u1", Some(json!({"userName": "alison"})));
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_json(resp).await;
        assert_eq!(body["userName"], "alison");
    }

    #[tokio::test]
    async fn delete_user_route_returns_no_content() {
        let service = Arc::new(StubService {
            delete_user: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(
                buffa_types::google::protobuf::Empty::default(),
            ))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("DELETE", "/scim/v2/Users/u1", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn list_groups_route_returns_groups() {
        let service = Arc::new(StubService {
            list_groups: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(
                crate::proto::iam::v1::ScimListGroupsResponse {
                    groups: vec![ScimGroup {
                        id: "g1".into(),
                        display_name: "admins".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("GET", "/scim/v2/Groups", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_json(resp).await;
        assert_eq!(body["totalResults"], 1);
    }

    #[tokio::test]
    async fn create_group_route_returns_group() {
        let service = Arc::new(StubService {
            create_group: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(ScimGroup {
                id: "g1".into(),
                display_name: "admins".into(),
                ..Default::default()
            }))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("POST", "/scim/v2/Groups", Some(json!({"displayName": "admins"})));
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_json(resp).await;
        assert_eq!(body["displayName"], "admins");
    }

    #[tokio::test]
    async fn get_group_route_returns_group() {
        let service = Arc::new(StubService {
            get_group: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(ScimGroup {
                id: "g1".into(),
                display_name: "admins".into(),
                ..Default::default()
            }))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("GET", "/scim/v2/Groups/g1", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_json(resp).await;
        assert_eq!(body["id"], "g1");
    }

    #[tokio::test]
    async fn update_group_route_returns_group() {
        let service = Arc::new(StubService {
            update_group: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(ScimGroup {
                id: "g1".into(),
                display_name: "super-admins".into(),
                ..Default::default()
            }))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("PUT", "/scim/v2/Groups/g1", Some(json!({"displayName": "super-admins"})));
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_json(resp).await;
        assert_eq!(body["displayName"], "super-admins");
    }

    #[tokio::test]
    async fn delete_group_route_returns_no_content() {
        let service = Arc::new(StubService {
            delete_group: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(
                buffa_types::google::protobuf::Empty::default(),
            ))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("DELETE", "/scim/v2/Groups/g1", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn route_maps_service_error_to_status() {
        let service = Arc::new(StubService {
            get_user: Arc::new(Mutex::new(Some(Err(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::NotFound,
                "not found",
            ))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = router(state);
        let req = authenticated_request("GET", "/scim/v2/Users/missing", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn resolve_tenant_returns_unauthorized_on_introspection_error() {
        let state = test_state(
            Some(Err(OryClientError::Ory {
                status: 401,
                message: "invalid token".into(),
            })),
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        let err = resolve_tenant(&state, &headers).await.unwrap_err();
        assert_eq!(error_status(&err), StatusCode::UNAUTHORIZED);
    }

    fn route_state_with_service_and_auth(
        service: Arc<dyn ScimServiceOps>,
        introspect: Result<Value, OryClientError>,
        mapping: Result<Option<String>, crate::db::DbError>,
    ) -> Arc<ScimState> {
        Arc::new(ScimState {
            service,
            hydra: Arc::new(StubHydra {
                introspect_result: Arc::new(Mutex::new(Some(introspect))),
            }),
            mappings: Arc::new(StubMappingStore {
                tenant_by_ory_id: Arc::new(Mutex::new(Some(mapping))),
            }),
        })
    }

    async fn assert_route_maps_service_error(
        method: &str,
        uri: &str,
        body: Option<Value>,
        service: Arc<dyn ScimServiceOps>,
    ) {
        let state = route_state_with_service_and_auth(
            service,
            Ok(json!({"active": true, "sub": "sub-1"})),
            Ok(Some("tenant-1".to_string())),
        );
        let mut router = router(state);
        let req = authenticated_request(method, uri, body);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_users_route_maps_service_error() {
        let service = Arc::new(StubService {
            list_users: Arc::new(Mutex::new(Some(Err(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::NotFound,
                "not found",
            ))))),
            ..Default::default()
        });
        assert_route_maps_service_error("GET", "/scim/v2/Users", None, service).await;
    }

    #[tokio::test]
    async fn create_user_route_maps_service_error() {
        let service = Arc::new(StubService {
            create_user: Arc::new(Mutex::new(Some(Err(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::NotFound,
                "not found",
            ))))),
            ..Default::default()
        });
        assert_route_maps_service_error("POST", "/scim/v2/Users", Some(json!({"userName": "alice"})), service).await;
    }

    #[tokio::test]
    async fn update_user_route_maps_service_error() {
        let service = Arc::new(StubService {
            update_user: Arc::new(Mutex::new(Some(Err(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::NotFound,
                "not found",
            ))))),
            ..Default::default()
        });
        assert_route_maps_service_error("PUT", "/scim/v2/Users/u1", Some(json!({"userName": "alison"})), service).await;
    }

    #[tokio::test]
    async fn delete_user_route_maps_service_error() {
        let service = Arc::new(StubService {
            delete_user: Arc::new(Mutex::new(Some(Err(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::NotFound,
                "not found",
            ))))),
            ..Default::default()
        });
        assert_route_maps_service_error("DELETE", "/scim/v2/Users/u1", None, service).await;
    }

    #[tokio::test]
    async fn list_groups_route_maps_service_error() {
        let service = Arc::new(StubService {
            list_groups: Arc::new(Mutex::new(Some(Err(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::NotFound,
                "not found",
            ))))),
            ..Default::default()
        });
        assert_route_maps_service_error("GET", "/scim/v2/Groups", None, service).await;
    }

    #[tokio::test]
    async fn create_group_route_maps_service_error() {
        let service = Arc::new(StubService {
            create_group: Arc::new(Mutex::new(Some(Err(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::NotFound,
                "not found",
            ))))),
            ..Default::default()
        });
        assert_route_maps_service_error("POST", "/scim/v2/Groups", Some(json!({"displayName": "admins"})), service).await;
    }

    #[tokio::test]
    async fn update_group_route_maps_service_error() {
        let service = Arc::new(StubService {
            update_group: Arc::new(Mutex::new(Some(Err(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::NotFound,
                "not found",
            ))))),
            ..Default::default()
        });
        assert_route_maps_service_error("PUT", "/scim/v2/Groups/g1", Some(json!({"displayName": "super-admins"})), service).await;
    }

    #[tokio::test]
    async fn delete_group_route_maps_service_error() {
        let service = Arc::new(StubService {
            delete_group: Arc::new(Mutex::new(Some(Err(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::NotFound,
                "not found",
            ))))),
            ..Default::default()
        });
        assert_route_maps_service_error("DELETE", "/scim/v2/Groups/g1", None, service).await;
    }

    #[tokio::test]
    async fn get_group_route_maps_service_error() {
        let service = Arc::new(StubService {
            get_group: Arc::new(Mutex::new(Some(Err(connectrpc::ConnectError::new(
                connectrpc::ErrorCode::NotFound,
                "not found",
            ))))),
            ..Default::default()
        });
        assert_route_maps_service_error("GET", "/scim/v2/Groups/g1", None, service).await;
    }
}
