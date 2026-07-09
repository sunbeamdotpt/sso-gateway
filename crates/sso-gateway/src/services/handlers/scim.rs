use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Extension, Json, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};

use crate::{
    auth::{AuthContext, SCOPE_SCIM_ADMIN, SCOPE_SCIM_READ},
    proto::iam::v1::{ScimGroup, ScimUser},
    services::scim::ScimServiceImpl,
};

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

/// Async trait for the SCIM service operations used by the HTTP handlers.
#[async_trait]
pub trait ScimServiceOps: Send + Sync + 'static {
    async fn list_users_http(
        &self,
        tenant_id: String,
    ) -> Result<
        connectrpc::Response<crate::proto::iam::v1::ScimListUsersResponse>,
        connectrpc::ConnectError,
    >;
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
    ) -> Result<
        connectrpc::Response<crate::proto::iam::v1::ScimListGroupsResponse>,
        connectrpc::ConnectError,
    >;
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
    ) -> Result<
        connectrpc::Response<crate::proto::iam::v1::ScimListUsersResponse>,
        connectrpc::ConnectError,
    > {
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
    ) -> Result<
        connectrpc::Response<crate::proto::iam::v1::ScimListGroupsResponse>,
        connectrpc::ConnectError,
    > {
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
}

impl ScimState {
    pub fn new(service: Arc<ScimServiceImpl>) -> Self {
        Self {
            service: service as Arc<dyn ScimServiceOps>,
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
    Extension(auth_ctx): Extension<AuthContext>,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> Result<Response<Body>, ScimError> {
    require_scope_any(&auth_ctx, &[SCOPE_SCIM_READ, SCOPE_SCIM_ADMIN])?;
    let resp = state.service.list_users_http(auth_ctx.tenant_id).await?;
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
    Extension(auth_ctx): Extension<AuthContext>,
    Json(user): Json<ScimUser>,
) -> Result<Response<Body>, ScimError> {
    require_scope(&auth_ctx, SCOPE_SCIM_ADMIN)?;
    let resp = state
        .service
        .create_user_http(auth_ctx.tenant_id, user)
        .await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn get_user(
    State(state): State<Arc<ScimState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Response<Body>, ScimError> {
    require_scope_any(&auth_ctx, &[SCOPE_SCIM_READ, SCOPE_SCIM_ADMIN])?;
    let resp = state.service.get_user_http(auth_ctx.tenant_id, id).await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn update_user(
    State(state): State<Arc<ScimState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(user): Json<ScimUser>,
) -> Result<Response<Body>, ScimError> {
    require_scope(&auth_ctx, SCOPE_SCIM_ADMIN)?;
    let resp = state
        .service
        .update_user_http(auth_ctx.tenant_id, id, user)
        .await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn delete_user(
    State(state): State<Arc<ScimState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Response<Body>, ScimError> {
    require_scope(&auth_ctx, SCOPE_SCIM_ADMIN)?;
    let _ = state
        .service
        .delete_user_http(auth_ctx.tenant_id, id)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn list_groups(
    State(state): State<Arc<ScimState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> Result<Response<Body>, ScimError> {
    require_scope_any(&auth_ctx, &[SCOPE_SCIM_READ, SCOPE_SCIM_ADMIN])?;
    let resp = state.service.list_groups_http(auth_ctx.tenant_id).await?;
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
    Extension(auth_ctx): Extension<AuthContext>,
    Json(group): Json<ScimGroup>,
) -> Result<Response<Body>, ScimError> {
    require_scope(&auth_ctx, SCOPE_SCIM_ADMIN)?;
    let resp = state
        .service
        .create_group_http(auth_ctx.tenant_id, group)
        .await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn get_group(
    State(state): State<Arc<ScimState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Response<Body>, ScimError> {
    require_scope_any(&auth_ctx, &[SCOPE_SCIM_READ, SCOPE_SCIM_ADMIN])?;
    let resp = state.service.get_group_http(auth_ctx.tenant_id, id).await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn update_group(
    State(state): State<Arc<ScimState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(group): Json<ScimGroup>,
) -> Result<Response<Body>, ScimError> {
    require_scope(&auth_ctx, SCOPE_SCIM_ADMIN)?;
    let resp = state
        .service
        .update_group_http(auth_ctx.tenant_id, id, group)
        .await?;
    Ok(scim_json(
        serde_json::to_value(resp.body).unwrap_or_default(),
    ))
}

async fn delete_group(
    State(state): State<Arc<ScimState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Response<Body>, ScimError> {
    require_scope(&auth_ctx, SCOPE_SCIM_ADMIN)?;
    let _ = state
        .service
        .delete_group_http(auth_ctx.tenant_id, id)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
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

fn require_scope(auth_ctx: &AuthContext, scope: &str) -> Result<(), ScimError> {
    if !auth_ctx.scopes.iter().any(|s| s == scope) {
        return Err(ScimError::Response(Box::new(scim_error(
            StatusCode::FORBIDDEN,
            &format!("missing required scope: {scope}"),
        ))));
    }
    Ok(())
}

fn require_scope_any(auth_ctx: &AuthContext, scopes: &[&str]) -> Result<(), ScimError> {
    if !auth_ctx.scopes.iter().any(|s| scopes.contains(&s.as_str())) {
        return Err(ScimError::Response(Box::new(scim_error(
            StatusCode::FORBIDDEN,
            &format!("missing required scope: one of {}", scopes.join(", ")),
        ))));
    }
    Ok(())
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
    use axum::extract::Request;
    use axum::http::header::AUTHORIZATION;
    use http_body_util::BodyExt;
    use std::sync::Mutex;

    use crate::auth::{IntrospectionResult, SCOPE_SCIM_ADMIN, SCOPE_SCIM_READ, TokenIntrospector};
    use crate::db::{IdMappingStore, SessionStore};
    use crate::middleware::auth_middleware;

    #[derive(Clone, Default)]
    struct StubIntrospector {
        result: Arc<Mutex<Option<Result<IntrospectionResult, crate::auth::AuthError>>>>,
    }

    #[async_trait]
    impl TokenIntrospector for StubIntrospector {
        async fn introspect(
            &self,
            _token: &str,
        ) -> Result<IntrospectionResult, crate::auth::AuthError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(crate::auth::AuthError::InactiveToken))
        }
    }

    #[derive(Clone, Default)]
    struct StubMappingStore {
        #[allow(clippy::type_complexity)]
        tenant_by_ory_id: Arc<Mutex<Option<Result<Option<String>, crate::db::DbError>>>>,
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

        async fn get_public_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, crate::db::DbError> {
            Ok("pub-sub-1".into())
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
            self.tenant_by_ory_id
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }
    }

    fn test_introspector() -> Arc<dyn TokenIntrospector> {
        introspector_with_scopes(vec![SCOPE_SCIM_READ.into(), SCOPE_SCIM_ADMIN.into()])
    }

    fn introspector_with_scopes(scopes: Vec<String>) -> Arc<dyn TokenIntrospector> {
        Arc::new(StubIntrospector {
            result: Arc::new(Mutex::new(Some(Ok(IntrospectionResult {
                active: true,
                sub: Some("sub-1".into()),
                scope: scopes,
                exp: None,
                authentication_methods: vec![],
            })))),
        })
    }

    #[derive(Clone, Default)]
    struct StubSessionStore;

    #[async_trait]
    impl SessionStore for StubSessionStore {
        async fn create(
            &self,
            _session_id: &str,
            _sub: &str,
            _tenant_id: &str,
            _amr: &str,
            _expires_at: time::OffsetDateTime,
        ) -> Result<(), crate::db::DbError> {
            Ok(())
        }

        async fn is_active(&self, _session_id: &str) -> Result<bool, crate::db::DbError> {
            Ok(true)
        }

        async fn revoke(&self, _session_id: &str) -> Result<(), crate::db::DbError> {
            Ok(())
        }

        async fn revoke_all_for_subject(&self, _sub: &str) -> Result<(), crate::db::DbError> {
            Ok(())
        }
    }

    fn test_session_store() -> Arc<dyn SessionStore> {
        Arc::new(StubSessionStore)
    }

    fn test_mappings() -> Arc<dyn IdMappingStore> {
        Arc::new(StubMappingStore {
            tenant_by_ory_id: Arc::new(Mutex::new(Some(Ok(Some("tenant-1".to_string()))))),
        })
    }

    fn auth_router(state: Arc<ScimState>) -> Router {
        router(state)
            .layer(axum::middleware::from_fn(auth_middleware))
            .layer(axum::Extension(test_introspector()))
            .layer(axum::Extension(
                crate::session_token::SessionTokenSigner::new(
                    "test-secret-that-is-at-least-32-bytes-long",
                    3600,
                    "https://gateway.example.com",
                ),
            ))
            .layer(axum::Extension(test_mappings()))
            .layer(axum::Extension(test_session_store()))
    }

    async fn body_to_json(resp: Response<Body>) -> Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
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
        assert!(
            resources
                .iter()
                .any(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:User")
        );
        assert!(
            resources
                .iter()
                .any(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:Group")
        );
    }

    type OptResp<T> = Arc<Mutex<Option<Result<connectrpc::Response<T>, connectrpc::ConnectError>>>>;

    #[derive(Clone, Default)]
    struct StubService {
        list_users: OptResp<crate::proto::iam::v1::ScimListUsersResponse>,
        create_user: OptResp<ScimUser>,
        get_user: OptResp<ScimUser>,
        update_user: OptResp<ScimUser>,
        delete_user: OptResp<buffa_types::google::protobuf::Empty>,
        list_groups: OptResp<crate::proto::iam::v1::ScimListGroupsResponse>,
        create_group: OptResp<ScimGroup>,
        get_group: OptResp<ScimGroup>,
        update_group: OptResp<ScimGroup>,
        delete_group: OptResp<buffa_types::google::protobuf::Empty>,
    }

    #[async_trait]
    impl ScimServiceOps for StubService {
        async fn list_users_http(
            &self,
            _tenant_id: String,
        ) -> Result<
            connectrpc::Response<crate::proto::iam::v1::ScimListUsersResponse>,
            connectrpc::ConnectError,
        > {
            self.list_users
                .lock()
                .unwrap()
                .take()
                .expect("list_users stub not configured")
        }
        async fn create_user_http(
            &self,
            _tenant_id: String,
            _user: ScimUser,
        ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
            self.create_user
                .lock()
                .unwrap()
                .take()
                .expect("create_user stub not configured")
        }
        async fn get_user_http(
            &self,
            _tenant_id: String,
            _id: String,
        ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
            self.get_user
                .lock()
                .unwrap()
                .take()
                .expect("get_user stub not configured")
        }
        async fn update_user_http(
            &self,
            _tenant_id: String,
            _id: String,
            _user: ScimUser,
        ) -> Result<connectrpc::Response<ScimUser>, connectrpc::ConnectError> {
            self.update_user
                .lock()
                .unwrap()
                .take()
                .expect("update_user stub not configured")
        }
        async fn delete_user_http(
            &self,
            _tenant_id: String,
            _id: String,
        ) -> Result<
            connectrpc::Response<buffa_types::google::protobuf::Empty>,
            connectrpc::ConnectError,
        > {
            self.delete_user
                .lock()
                .unwrap()
                .take()
                .expect("delete_user stub not configured")
        }
        async fn list_groups_http(
            &self,
            _tenant_id: String,
        ) -> Result<
            connectrpc::Response<crate::proto::iam::v1::ScimListGroupsResponse>,
            connectrpc::ConnectError,
        > {
            self.list_groups
                .lock()
                .unwrap()
                .take()
                .expect("list_groups stub not configured")
        }
        async fn create_group_http(
            &self,
            _tenant_id: String,
            _group: ScimGroup,
        ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
            self.create_group
                .lock()
                .unwrap()
                .take()
                .expect("create_group stub not configured")
        }
        async fn get_group_http(
            &self,
            _tenant_id: String,
            _id: String,
        ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
            self.get_group
                .lock()
                .unwrap()
                .take()
                .expect("get_group stub not configured")
        }
        async fn update_group_http(
            &self,
            _tenant_id: String,
            _id: String,
            _group: ScimGroup,
        ) -> Result<connectrpc::Response<ScimGroup>, connectrpc::ConnectError> {
            self.update_group
                .lock()
                .unwrap()
                .take()
                .expect("update_group stub not configured")
        }
        async fn delete_group_http(
            &self,
            _tenant_id: String,
            _id: String,
        ) -> Result<
            connectrpc::Response<buffa_types::google::protobuf::Empty>,
            connectrpc::ConnectError,
        > {
            self.delete_group
                .lock()
                .unwrap()
                .take()
                .expect("delete_group stub not configured")
        }
    }

    fn route_state_with_service(service: Arc<dyn ScimServiceOps>) -> Arc<ScimState> {
        Arc::new(ScimState { service })
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
        let mut router = auth_router(state);
        let req = authenticated_request("GET", "/scim/v2/ServiceProviderConfig", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_exposes_resource_types() {
        let state = route_state_with_service(Arc::new(StubService::default()));
        let mut router = auth_router(state);
        let req = authenticated_request("GET", "/scim/v2/ResourceTypes", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_exposes_schemas() {
        let state = route_state_with_service(Arc::new(StubService::default()));
        let mut router = auth_router(state);
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
        let mut router = auth_router(state);
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
        let mut router = auth_router(state);
        let req =
            authenticated_request("POST", "/scim/v2/Users", Some(json!({"userName": "alice"})));
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
        let mut router = auth_router(state);
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
        let mut router = auth_router(state);
        let req = authenticated_request(
            "PUT",
            "/scim/v2/Users/u1",
            Some(json!({"userName": "alison"})),
        );
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
        let mut router = auth_router(state);
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
        let mut router = auth_router(state);
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
        let mut router = auth_router(state);
        let req = authenticated_request(
            "POST",
            "/scim/v2/Groups",
            Some(json!({"displayName": "admins"})),
        );
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
        let mut router = auth_router(state);
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
        let mut router = auth_router(state);
        let req = authenticated_request(
            "PUT",
            "/scim/v2/Groups/g1",
            Some(json!({"displayName": "super-admins"})),
        );
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
        let mut router = auth_router(state);
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
        let mut router = auth_router(state);
        let req = authenticated_request("GET", "/scim/v2/Users/missing", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    async fn assert_route_maps_service_error(
        method: &str,
        uri: &str,
        body: Option<Value>,
        service: Arc<dyn ScimServiceOps>,
    ) {
        let state = route_state_with_service(service);
        let mut router = auth_router(state);
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
        assert_route_maps_service_error(
            "POST",
            "/scim/v2/Users",
            Some(json!({"userName": "alice"})),
            service,
        )
        .await;
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
        assert_route_maps_service_error(
            "PUT",
            "/scim/v2/Users/u1",
            Some(json!({"userName": "alison"})),
            service,
        )
        .await;
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
        assert_route_maps_service_error(
            "POST",
            "/scim/v2/Groups",
            Some(json!({"displayName": "admins"})),
            service,
        )
        .await;
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
        assert_route_maps_service_error(
            "PUT",
            "/scim/v2/Groups/g1",
            Some(json!({"displayName": "super-admins"})),
            service,
        )
        .await;
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

    fn auth_router_with_scopes(state: Arc<ScimState>, scopes: Vec<String>) -> Router {
        router(state)
            .layer(axum::middleware::from_fn(auth_middleware))
            .layer(axum::Extension(introspector_with_scopes(scopes)))
            .layer(axum::Extension(
                crate::session_token::SessionTokenSigner::new(
                    "test-secret-that-is-at-least-32-bytes-long",
                    3600,
                    "https://gateway.example.com",
                ),
            ))
            .layer(axum::Extension(test_mappings()))
            .layer(axum::Extension(test_session_store()))
    }

    #[tokio::test]
    async fn create_user_route_rejects_read_only_scope() {
        let state = route_state_with_service(Arc::new(StubService::default()));
        let mut router = auth_router_with_scopes(state, vec![SCOPE_SCIM_READ.into()]);
        let req =
            authenticated_request("POST", "/scim/v2/Users", Some(json!({"userName": "alice"})));
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_user_route_rejects_read_only_scope() {
        let state = route_state_with_service(Arc::new(StubService::default()));
        let mut router = auth_router_with_scopes(state, vec![SCOPE_SCIM_READ.into()]);
        let req = authenticated_request("DELETE", "/scim/v2/Users/u1", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn update_group_route_rejects_read_only_scope() {
        let state = route_state_with_service(Arc::new(StubService::default()));
        let mut router = auth_router_with_scopes(state, vec![SCOPE_SCIM_READ.into()]);
        let req = authenticated_request(
            "PUT",
            "/scim/v2/Groups/g1",
            Some(json!({"displayName": "super-admins"})),
        );
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_group_route_accepts_admin_scope() {
        let service = Arc::new(StubService {
            create_group: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(ScimGroup {
                id: "g1".into(),
                display_name: "admins".into(),
                ..Default::default()
            }))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = auth_router_with_scopes(state, vec![SCOPE_SCIM_ADMIN.into()]);
        let req = authenticated_request(
            "POST",
            "/scim/v2/Groups",
            Some(json!({"displayName": "admins"})),
        );
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_user_route_accepts_read_scope() {
        let service = Arc::new(StubService {
            get_user: Arc::new(Mutex::new(Some(Ok(connectrpc::Response::new(ScimUser {
                id: "u1".into(),
                user_name: "alice".into(),
                ..Default::default()
            }))))),
            ..Default::default()
        });
        let state = route_state_with_service(service);
        let mut router = auth_router_with_scopes(state, vec![SCOPE_SCIM_READ.into()]);
        let req = authenticated_request("GET", "/scim/v2/Users/u1", None);
        let resp = call(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
