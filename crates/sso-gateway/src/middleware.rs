use async_trait::async_trait;
use axum::{
    Extension,
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use connectrpc::RequestContext;
use serde_json::Value;

use crate::db::{AuditLogRepo, DbError, IdMappingRepo, IdMappingStore, TenantApiKeyRepo, TenantApiKeyStore};
use sso_ory_client::{KratosClient, error::OryClientError};
use std::sync::Arc;
use sunbeam_g2v::error::ServiceError;

pub const TENANT_ID_HEADER: &str = "x-tenant-id";
pub const API_KEY_HEADER: &str = "x-api-key";

#[derive(Clone, Debug)]
pub struct TenantId(pub String);

#[derive(Clone, Debug)]
pub struct ApiKeyContext {
    pub key_id: String,
    pub tenant_id: String,
    pub scopes: Vec<String>,
}

#[async_trait]
trait SessionClient: Send + Sync {
    async fn to_session(
        &self,
        cookie: Option<&str>,
        token: Option<&str>,
    ) -> Result<Value, OryClientError>;
}

#[async_trait]
impl SessionClient for KratosClient {
    async fn to_session(
        &self,
        cookie: Option<&str>,
        token: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.to_session(cookie, token).await
    }
}

fn is_public_path(path: &str) -> bool {
    path.starts_with("/.well-known/")
        || path.starts_with("/oauth2/")
        || path.starts_with("/scim/")
        || path.starts_with("/saml/")
}

pub async fn auth_middleware(
    Extension(api_keys): Extension<TenantApiKeyRepo>,
    Extension(kratos): Extension<Arc<KratosClient>>,
    Extension(mappings): Extension<IdMappingRepo>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    // Public OAuth2/OIDC discovery and browser flows perform their own tenant
    // validation (via client_id or explicit x-tenant-id in handlers).
    if is_public_path(path) {
        return next.run(request).await;
    }

    let api_key_value = request
        .headers()
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok());

    if let Some(key) = api_key_value {
        match authenticate_api_key(&api_keys, key).await {
            Ok(ctx) => {
                request
                    .extensions_mut()
                    .insert(TenantId(ctx.tenant_id.clone()));
                request.extensions_mut().insert(ctx);
            }
            Err(resp) => return *resp,
        }
        return next.run(request).await;
    }

    let cookie_value = request
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok());

    if let Some(cookie) = cookie_value {
        match authenticate_session_cookie(kratos.as_ref(), &mappings, cookie).await {
            Ok(tenant_id) => {
                request.extensions_mut().insert(TenantId(tenant_id));
                return next.run(request).await;
            }
            Err(resp) => return *resp,
        }
    }

    let tenant_value = request
        .headers()
        .get(TENANT_ID_HEADER)
        .and_then(|v| v.to_str().ok());

    match tenant_value {
        Some(value) => match parse_tenant_id(value) {
            Ok(tenant_id) => {
                request.extensions_mut().insert(TenantId(tenant_id));
            }
            Err(resp) => return *resp,
        },
        None => {
            return auth_error(
                StatusCode::UNAUTHORIZED,
                "missing x-tenant-id or x-api-key header",
            );
        }
    }

    next.run(request).await
}

async fn authenticate_session_cookie(
    client: &dyn SessionClient,
    mappings: &dyn IdMappingStore,
    cookie: &str,
) -> Result<String, Box<Response>> {
    let session = client.to_session(Some(cookie), None).await.map_err(|_| {
        Box::new(auth_error(
            StatusCode::UNAUTHORIZED,
            "invalid or expired session cookie",
        ))
    })?;

    let ory_identity_id = session["identity"]["id"].as_str().unwrap_or("");

    if ory_identity_id.is_empty() {
        return Err(Box::new(auth_error(
            StatusCode::UNAUTHORIZED,
            "session missing identity",
        )));
    }

    let tenant_id = mappings
        .get_tenant_id_by_ory_id("kratos", ory_identity_id)
        .await
        .map_err(|_| {
            Box::new(auth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to resolve tenant",
            ))
        })?
        .ok_or_else(|| {
            Box::new(auth_error(
                StatusCode::UNAUTHORIZED,
                "identity not registered",
            ))
        })?;

    Ok(tenant_id)
}

async fn authenticate_api_key(
    repo: &dyn TenantApiKeyStore,
    key: &str,
) -> Result<ApiKeyContext, Box<Response>> {
    let hash = hash_api_key(key);
    match repo.get_by_hash(&hash).await {
        Ok(row) => Ok(ApiKeyContext {
            key_id: row.id,
            tenant_id: row.tenant_id,
            scopes: row.scopes,
        }),
        Err(DbError::ApiKeyNotFound) => Err(Box::new(auth_error(
            StatusCode::UNAUTHORIZED,
            "invalid or expired api key",
        ))),
        Err(_) => Err(Box::new(auth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to authenticate api key",
        ))),
    }
}

pub fn hash_api_key(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_tenant_id(value: &str) -> Result<String, Box<Response>> {
    if value.is_empty() {
        return Err(Box::new(auth_error(
            StatusCode::BAD_REQUEST,
            "missing tenant id",
        )));
    }
    if ulid::Ulid::from_string(value).is_err() {
        return Err(Box::new(auth_error(
            StatusCode::BAD_REQUEST,
            "invalid tenant id",
        )));
    }
    Ok(value.to_string())
}

fn auth_error(status: StatusCode, message: &'static str) -> Response {
    let body = Body::from(format!("{{\"error\":\"{message}\"}}"));
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

fn build_audit_metadata(status: StatusCode) -> serde_json::Value {
    serde_json::json!({
        "status": status.as_u16(),
    })
}

/// Best-effort audit logging middleware.
///
/// Captures the HTTP method, path, resolved tenant, authenticated actor, and
/// response status. Insertions are performed in a spawned task so the response
/// is never blocked on the database.
pub async fn audit_middleware(
    Extension(repo): Extension<AuditLogRepo>,
    request: Request,
    next: Next,
) -> Response {
    let tenant_id = request
        .extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .or_else(|| {
            request
                .headers()
                .get(TENANT_ID_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        });
    let actor = request
        .extensions()
        .get::<ApiKeyContext>()
        .map(|c| c.key_id.clone());
    let method = request.method().to_string();
    let resource = request.uri().path().to_string();

    let response = next.run(request).await;

    let outcome = if response.status().is_success() {
        "success"
    } else {
        "failure"
    };
    let metadata = build_audit_metadata(response.status());

    let repo = repo.clone();
    tokio::spawn(async move {
        if let Err(err) = repo
            .insert(
                tenant_id.as_deref(),
                actor.as_deref(),
                &method,
                &resource,
                outcome,
                metadata,
            )
            .await
        {
            tracing::warn!(%err, "audit log insertion failed");
        }
    });

    response
}

/// Require a scope when the request was authenticated with an API key.
/// Requests that only supplied `X-Tenant-Id` (e.g. bootstrap) bypass scope checks.
pub fn require_scope(ctx: &RequestContext, scope: &str) -> Result<(), ServiceError> {
    if let Some(api_key) = ctx.extensions().get::<ApiKeyContext>()
        && !api_key.scopes.iter().any(|s| s == scope)
    {
        return Err(ServiceError::PermissionDenied(format!(
            "missing required scope: {scope}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{IdMappingRow, TenantApiKeyRow};
    use std::sync::Mutex;

    #[test]
    fn hash_api_key_is_deterministic_and_hex() {
        let h1 = hash_api_key("my-secret-key");
        let h2 = hash_api_key("my-secret-key");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_api_key_differs_for_different_keys() {
        let h1 = hash_api_key("key-one");
        let h2 = hash_api_key("key-two");
        assert_ne!(h1, h2);
    }

    #[test]
    fn parse_tenant_id_accepts_valid_ulid() {
        let valid = ulid::Ulid::new().to_string();
        assert_eq!(parse_tenant_id(&valid).unwrap(), valid);
    }

    #[test]
    fn parse_tenant_id_rejects_empty() {
        let err = parse_tenant_id("").unwrap_err();
        let resp = *err;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_tenant_id_rejects_invalid_ulid() {
        let err = parse_tenant_id("not-a-ulid").unwrap_err();
        let resp = *err;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn require_scope_allows_when_no_api_key_context() {
        let ctx = RequestContext::default();
        assert!(require_scope(&ctx, "tenant:write").is_ok());
    }

    #[test]
    fn require_scope_enforces_scope_for_api_key() {
        let mut ctx = RequestContext::default();
        ctx.extensions_mut().insert(ApiKeyContext {
            key_id: "key-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            scopes: vec!["tenant:read".to_string()],
        });
        assert!(require_scope(&ctx, "tenant:read").is_ok());
        let err = require_scope(&ctx, "tenant:write").unwrap_err();
        assert!(matches!(err, ServiceError::PermissionDenied(_)));
    }

    #[test]
    fn auth_error_builds_json_response() {
        let resp = auth_error(StatusCode::FORBIDDEN, "no");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );
    }

    #[test]
    fn is_public_path_matches_public_prefixes() {
        assert!(is_public_path("/.well-known/openid-configuration"));
        assert!(is_public_path("/oauth2/auth"));
        assert!(is_public_path("/scim/v2/Users"));
        assert!(is_public_path("/saml/metadata"));
        assert!(!is_public_path("/iam/v1/tenants"));
    }

    #[test]
    fn build_audit_metadata_contains_status() {
        let metadata = build_audit_metadata(StatusCode::CREATED);
        assert_eq!(metadata["status"], 201);
    }

    struct StubApiKeyStore(Mutex<Option<Result<TenantApiKeyRow, DbError>>>);

    #[async_trait]
    impl TenantApiKeyStore for StubApiKeyStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _name: &str,
            _key_hash: &str,
            _scopes: &[String],
            _expires_at: Option<time::OffsetDateTime>,
        ) -> Result<TenantApiKeyRow, DbError> {
            self.0
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(DbError::ApiKeyNotFound))
        }

        async fn get_by_hash(&self, _key_hash: &str) -> Result<TenantApiKeyRow, DbError> {
            self.0
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(DbError::ApiKeyNotFound))
        }
    }

    fn dummy_api_key_row() -> TenantApiKeyRow {
        TenantApiKeyRow {
            id: "key-1".into(),
            tenant_id: "tenant-1".into(),
            key_hash: hash_api_key("secret"),
            name: "test".into(),
            scopes: vec!["tenant:read".into()],
            expires_at: None,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    #[tokio::test]
    async fn authenticate_api_key_returns_context_for_valid_key() {
        let repo = StubApiKeyStore(Mutex::new(Some(Ok(dummy_api_key_row()))));
        let ctx = authenticate_api_key(&repo, "secret").await.unwrap();
        assert_eq!(ctx.key_id, "key-1");
        assert_eq!(ctx.tenant_id, "tenant-1");
        assert_eq!(ctx.scopes, vec!["tenant:read".to_string()]);
    }

    #[tokio::test]
    async fn authenticate_api_key_returns_unauthorized_for_unknown_key() {
        let repo = StubApiKeyStore(Mutex::new(Some(Err(DbError::ApiKeyNotFound))));
        let err = authenticate_api_key(&repo, "secret").await.unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authenticate_api_key_returns_internal_for_db_error() {
        let repo =
            StubApiKeyStore(Mutex::new(Some(Err(DbError::Sqlx(sqlx::Error::PoolTimedOut)))));
        let err = authenticate_api_key(&repo, "secret").await.unwrap_err();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    struct StubSessionClient(Mutex<Option<Result<Value, OryClientError>>>);

    #[async_trait]
    impl SessionClient for StubSessionClient {
        async fn to_session(
            &self,
            _cookie: Option<&str>,
            _token: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.0
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(OryClientError::MissingTenant))
        }
    }

    struct StubIdMappingStore(Mutex<Option<Result<Option<String>, DbError>>>);

    #[async_trait]
    impl IdMappingStore for StubIdMappingStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
            _ory_global_id: &str,
        ) -> Result<IdMappingRow, DbError> {
            Ok(IdMappingRow {
                id: "m1".into(),
                tenant_id: "tenant-1".into(),
                backend: "kratos".into(),
                public_id: "pub".into(),
                ory_global_id: "ory".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })
        }

        async fn get_ory_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<String, DbError> {
            Ok("ory".into())
        }

        async fn get_public_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, DbError> {
            Ok("pub".into())
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<(), DbError> {
            Ok(())
        }

        async fn list_public_ids(
            &self,
            _tenant_id: &str,
            _backend: &str,
        ) -> Result<Vec<String>, DbError> {
            Ok(vec![])
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, DbError> {
            self.0
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Ok(None))
        }
    }

    fn session_with_identity(id: &str) -> Value {
        serde_json::json!({
            "id": "session-1",
            "identity": { "id": id }
        })
    }

    #[tokio::test]
    async fn authenticate_session_cookie_resolves_registered_identity() {
        let client = StubSessionClient(Mutex::new(Some(Ok(session_with_identity("identity-1")))));
        let mappings = StubIdMappingStore(Mutex::new(Some(Ok(Some("tenant-1".into())))));
        let tenant = authenticate_session_cookie(&client, &mappings, "ory_session=abc")
            .await
            .unwrap();
        assert_eq!(tenant, "tenant-1");
    }

    #[tokio::test]
    async fn authenticate_session_cookie_rejects_invalid_session() {
        let client = StubSessionClient(Mutex::new(Some(Err(OryClientError::Ory {
            status: 401,
            message: "no session".into(),
        }))));
        let mappings = StubIdMappingStore(Mutex::new(Some(Ok(None))));
        let err = authenticate_session_cookie(&client, &mappings, "ory_session=abc")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authenticate_session_cookie_rejects_missing_identity() {
        let client = StubSessionClient(Mutex::new(Some(Ok(serde_json::json!({ "identity": {} })))));
        let mappings = StubIdMappingStore(Mutex::new(Some(Ok(None))));
        let err = authenticate_session_cookie(&client, &mappings, "ory_session=abc")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authenticate_session_cookie_rejects_unregistered_identity() {
        let client = StubSessionClient(Mutex::new(Some(Ok(session_with_identity("identity-1")))));
        let mappings = StubIdMappingStore(Mutex::new(Some(Ok(None))));
        let err = authenticate_session_cookie(&client, &mappings, "ory_session=abc")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authenticate_session_cookie_returns_internal_for_mapping_db_error() {
        let client = StubSessionClient(Mutex::new(Some(Ok(session_with_identity("identity-1")))));
        let mappings = StubIdMappingStore(Mutex::new(Some(Err(DbError::Sqlx(
            sqlx::Error::PoolTimedOut,
        )))));
        let err = authenticate_session_cookie(&client, &mappings, "ory_session=abc")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    mod middleware_integration {
        use axum::{Router, body::Body, http::Request, middleware::from_fn, routing::get};
        use tower::ServiceExt;

        use super::*;
        use crate::{
            db::{IdMappingRepo, TenantApiKeyRepo},
            test_support::{create_test_tenant, postgres_pool},
        };

        async fn ok_handler() -> &'static str {
            "ok"
        }

        fn api_key_router(
            api_keys: TenantApiKeyRepo,
            kratos: Arc<KratosClient>,
            mappings: IdMappingRepo,
        ) -> Router {
            Router::new()
                .route("/", get(ok_handler))
                .route("/protected", get(ok_handler))
                .route("/.well-known/openid-configuration", get(ok_handler))
                .layer(from_fn(auth_middleware))
                .layer(Extension(api_keys))
                .layer(Extension(kratos))
                .layer(Extension(mappings))
        }

        #[tokio::test]
        async fn public_path_bypasses_auth() {
            let router = api_key_router(
                TenantApiKeyRepo::new(postgres_pool().await),
                Arc::new(KratosClient::new("http://127.0.0.1:4434").unwrap()),
                IdMappingRepo::new(postgres_pool().await),
            );
            let response = router
                .oneshot(Request::get("/.well-known/openid-configuration").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn missing_auth_returns_unauthorized() {
            let router = api_key_router(
                TenantApiKeyRepo::new(postgres_pool().await),
                Arc::new(KratosClient::new("http://127.0.0.1:4434").unwrap()),
                IdMappingRepo::new(postgres_pool().await),
            );
            let response = router
                .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn valid_api_key_authenticates() {
            let pool = postgres_pool().await;
            let tenant = format!("tenant-{}", ulid::Ulid::new());
            create_test_tenant(&pool, &tenant).await;
            let api_keys = TenantApiKeyRepo::new(pool);
            api_keys
                .create(&tenant, "test-key", &hash_api_key("secret"), &["tenant:read".to_string()], None)
                .await
                .unwrap();

            let router = api_key_router(
                api_keys.clone(),
                Arc::new(KratosClient::new("http://127.0.0.1:4434").unwrap()),
                IdMappingRepo::new(postgres_pool().await),
            );
            let response = router
                .oneshot(
                    Request::get("/protected")
                        .header(API_KEY_HEADER, "secret")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn invalid_api_key_returns_unauthorized() {
            let router = api_key_router(
                TenantApiKeyRepo::new(postgres_pool().await),
                Arc::new(KratosClient::new("http://127.0.0.1:4434").unwrap()),
                IdMappingRepo::new(postgres_pool().await),
            );
            let response = router
                .oneshot(
                    Request::get("/protected")
                        .header(API_KEY_HEADER, "bad-secret")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn valid_tenant_header_authenticates() {
            let tenant = ulid::Ulid::new().to_string();
            let router = api_key_router(
                TenantApiKeyRepo::new(postgres_pool().await),
                Arc::new(KratosClient::new("http://127.0.0.1:4434").unwrap()),
                IdMappingRepo::new(postgres_pool().await),
            );
            let response = router
                .oneshot(
                    Request::get("/protected")
                        .header(TENANT_ID_HEADER, &tenant)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn invalid_tenant_header_returns_bad_request() {
            let router = api_key_router(
                TenantApiKeyRepo::new(postgres_pool().await),
                Arc::new(KratosClient::new("http://127.0.0.1:4434").unwrap()),
                IdMappingRepo::new(postgres_pool().await),
            );
            let response = router
                .oneshot(
                    Request::get("/protected")
                        .header(TENANT_ID_HEADER, "not-a-ulid")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn audit_middleware_records_and_returns_ok() {
            let audit = AuditLogRepo::new(postgres_pool().await);
            let router = Router::new()
                .route("/", get(ok_handler))
                .layer(from_fn(audit_middleware))
                .layer(Extension(audit));
            let response = router
                .oneshot(Request::get("/").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }
}
