use axum::{
    Extension,
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::auth::{
    AuthContext, TokenIntrospector, bearer_token, build_auth_context, resolve_tenant_from_subject,
};
use crate::db::{AuditLogRepo, IdMappingStore, SessionStore};
use crate::session_token::SessionTokenSigner;

pub const TENANT_ID_HEADER: &str = "x-tenant-id";

#[derive(Clone, Debug)]
pub struct TenantId(pub String);

/// Public paths that skip the shared bearer-token middleware.
///
/// These endpoints perform their own protocol-level authentication (OAuth2
/// client credentials, SAML assertions, OIDC discovery) or are discovery
/// documents.
fn is_public_path(path: &str) -> bool {
    match path {
        "/.well-known/openid-configuration" | "/.well-known/jwks.json" => true,
        "/oauth2/auth" | "/oauth2/token" | "/oauth2/revoke" | "/oauth2/userinfo" => true,
        "/saml/metadata" | "/saml/acs" | "/saml/sso" => true,
        "/callbacks/oidc" | "/callbacks/oauth2" => true,
        "/scim/v2/ServiceProviderConfig" | "/scim/v2/ResourceTypes" | "/scim/v2/Schemas" => true,
        "/health" | "/health/ready" | "/health/live" => true,
        _ => path.starts_with("/oauth2/device/"),
    }
}

const SESSION_COOKIE_NAME: &str = "__Host-sso_session";

pub async fn auth_middleware(
    Extension(introspector): Extension<Arc<dyn TokenIntrospector>>,
    Extension(mappings): Extension<Arc<dyn IdMappingStore>>,
    Extension(session_signer): Extension<SessionTokenSigner>,
    Extension(session_store): Extension<Arc<dyn SessionStore>>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if is_public_path(path) {
        return next.run(request).await;
    }

    let auth_result = if let Some(token) = bearer_token(request.headers()) {
        authenticate_bearer_token(introspector.as_ref(), mappings.as_ref(), &token).await
    } else if let Some(cookie) = session_cookie(request.headers()) {
        authenticate_session_cookie(&session_signer, session_store.as_ref(), cookie).await
    } else {
        return auth_error(StatusCode::UNAUTHORIZED);
    };

    match auth_result {
        Ok(ctx) => {
            request
                .extensions_mut()
                .insert(TenantId(ctx.tenant_id.clone()));
            request.extensions_mut().insert(AuthOutcome::Success);
            request.extensions_mut().insert(ctx);
        }
        Err(resp) => {
            request.extensions_mut().insert(AuthOutcome::Failure);
            return *resp;
        }
    }

    next.run(request).await
}

/// Outcome of authentication, recorded by the audit middleware.
#[derive(Clone, Debug)]
pub enum AuthOutcome {
    Success,
    Failure,
}

/// Extract the gateway session cookie value, if present.
fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (name, value) = cookie.trim().split_once('=')?;
                if name == SESSION_COOKIE_NAME {
                    Some(value.to_string())
                } else {
                    None
                }
            })
        })
}

async fn authenticate_session_cookie(
    signer: &SessionTokenSigner,
    session_store: &dyn SessionStore,
    cookie: String,
) -> Result<AuthContext, Box<Response>> {
    let claims = signer.verify(&cookie).map_err(|err| {
        tracing::debug!(%err, "session cookie verification failed");
        Box::new(auth_error(StatusCode::UNAUTHORIZED))
    })?;

    let active = session_store.is_active(&claims.sid).await.map_err(|err| {
        tracing::warn!(%err, "session store lookup failed");
        Box::new(auth_error(StatusCode::INTERNAL_SERVER_ERROR))
    })?;

    if !active {
        return Err(Box::new(auth_error(StatusCode::UNAUTHORIZED)));
    }

    Ok(build_auth_context(
        claims.tenant_id,
        claims.sub,
        vec![],
        &cookie,
    ))
}

async fn authenticate_bearer_token(
    introspector: &dyn TokenIntrospector,
    mappings: &dyn IdMappingStore,
    token: &str,
) -> Result<AuthContext, Box<Response>> {
    let introspection = introspector.introspect(token).await.map_err(|err| {
        tracing::debug!(%err, "token introspection failed");
        Box::new(auth_error(StatusCode::UNAUTHORIZED))
    })?;

    if !introspection.active {
        return Err(Box::new(auth_error(StatusCode::UNAUTHORIZED)));
    }

    let subject = introspection.sub.ok_or_else(|| {
        tracing::debug!("introspection response missing subject");
        Box::new(auth_error(StatusCode::UNAUTHORIZED))
    })?;

    let tenant_id = resolve_tenant_from_subject(mappings, &subject)
        .await
        .map_err(|err| {
            tracing::debug!(%err, "failed to resolve tenant for subject");
            match err {
                crate::auth::AuthError::UnknownSubject => {
                    Box::new(auth_error(StatusCode::UNAUTHORIZED))
                }
                _ => Box::new(auth_error(StatusCode::INTERNAL_SERVER_ERROR)),
            }
        })?;

    Ok(build_auth_context(
        tenant_id,
        subject,
        introspection.scope,
        token,
    ))
}

pub fn auth_error(status: StatusCode) -> Response {
    let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
        "internal server error"
    } else {
        "unauthorized"
    };
    let body = Body::from(format!("{{\"error\":\"{}\"}}", message));
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
        .get::<AuthContext>()
        .map(|c| c.tenant_id.clone())
        .or_else(|| request.extensions().get::<TenantId>().map(|t| t.0.clone()))
        .or_else(|| {
            request
                .headers()
                .get(TENANT_ID_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        });
    let actor = request
        .extensions()
        .get::<AuthContext>()
        .map(|c| c.subject.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::IntrospectionResult;
    use crate::session_token::SessionTokenSigner;
    use axum::{Extension, Router, body::Body, http::Request, middleware::from_fn, routing::get};
    use std::sync::Mutex;
    use tower::ServiceExt;

    struct StubIntrospector(Mutex<Option<Result<IntrospectionResult, crate::auth::AuthError>>>);

    #[async_trait::async_trait]
    impl TokenIntrospector for StubIntrospector {
        async fn introspect(
            &self,
            _token: &str,
        ) -> Result<IntrospectionResult, crate::auth::AuthError> {
            self.0
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(crate::auth::AuthError::InactiveToken))
        }
    }

    struct StubSessionStore(Mutex<Option<Result<bool, crate::db::DbError>>>);

    #[async_trait::async_trait]
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
            self.0.lock().unwrap().take().unwrap_or(Ok(true))
        }

        async fn revoke(&self, _session_id: &str) -> Result<(), crate::db::DbError> {
            Ok(())
        }

        async fn revoke_all_for_subject(&self, _sub: &str) -> Result<(), crate::db::DbError> {
            Ok(())
        }
    }

    struct StubMappingStore(Mutex<Option<Result<Option<String>, crate::db::DbError>>>);

    #[async_trait::async_trait]
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
            self.0.lock().unwrap().take().unwrap_or(Ok(None))
        }
    }

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn test_router(
        introspector: Arc<dyn TokenIntrospector>,
        mappings: Arc<dyn IdMappingStore>,
    ) -> Router {
        Router::new()
            .route("/protected", get(ok_handler))
            .route("/.well-known/openid-configuration", get(ok_handler))
            .route("/oauth2/auth", get(ok_handler))
            .layer(from_fn(auth_middleware))
            .layer(Extension(introspector))
            .layer(Extension(SessionTokenSigner::new(
                "test-secret-that-is-at-least-32-bytes-long",
                3600,
                "https://gateway.example.com",
            )))
            .layer(Extension(
                Arc::new(StubSessionStore(Mutex::new(Some(Ok(true))))) as Arc<dyn SessionStore>,
            ))
            .layer(Extension(mappings))
    }

    #[test]
    fn is_public_path_matches_public_routes() {
        assert!(is_public_path("/.well-known/openid-configuration"));
        assert!(is_public_path("/.well-known/jwks.json"));
        assert!(is_public_path("/oauth2/auth"));
        assert!(is_public_path("/oauth2/token"));
        assert!(is_public_path("/oauth2/device/auth"));
        assert!(is_public_path("/oauth2/revoke"));
        assert!(!is_public_path("/oauth2/introspect"));
        assert!(is_public_path("/oauth2/userinfo"));
        assert!(is_public_path("/saml/metadata"));
        assert!(is_public_path("/saml/acs"));
        assert!(is_public_path("/saml/sso"));
        assert!(is_public_path("/callbacks/oidc"));
        assert!(is_public_path("/callbacks/oauth2"));
        assert!(is_public_path("/scim/v2/ServiceProviderConfig"));
        assert!(is_public_path("/scim/v2/ResourceTypes"));
        assert!(is_public_path("/scim/v2/Schemas"));
        assert!(is_public_path("/health"));
        assert!(is_public_path("/health/ready"));
        assert!(is_public_path("/health/live"));
        assert!(!is_public_path("/iam/v1/tenants"));
    }

    #[test]
    fn build_audit_metadata_contains_status() {
        let metadata = build_audit_metadata(StatusCode::CREATED);
        assert_eq!(metadata["status"], 201);
    }

    #[tokio::test]
    async fn public_path_bypasses_auth() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(None))),
            Arc::new(StubMappingStore(Mutex::new(None))),
        );
        let response = router
            .oneshot(
                Request::get("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_token_or_cookie_returns_unauthorized() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(None))),
            Arc::new(StubMappingStore(Mutex::new(None))),
        );
        let response = router
            .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_session_cookie_authenticates() {
        let signer = SessionTokenSigner::new(
            "test-secret-that-is-at-least-32-bytes-long",
            3600,
            "https://gateway.example.com",
        );
        let (token, _) = signer.issue("public-1", "tenant-1", "oidc").unwrap();
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(None))),
            Arc::new(StubMappingStore(Mutex::new(None))),
        );
        let response = router
            .oneshot(
                Request::get("/protected")
                    .header("Cookie", format!("__Host-sso_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_session_cookie_returns_unauthorized() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(None))),
            Arc::new(StubMappingStore(Mutex::new(None))),
        );
        let response = router
            .oneshot(
                Request::get("/protected")
                    .header("Cookie", "__Host-sso_session=not-a-valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoked_session_cookie_returns_unauthorized() {
        let signer = SessionTokenSigner::new(
            "test-secret-that-is-at-least-32-bytes-long",
            3600,
            "https://gateway.example.com",
        );
        let (token, _) = signer.issue("public-1", "tenant-1", "oidc").unwrap();
        let router = Router::new()
            .route("/protected", get(ok_handler))
            .layer(from_fn(auth_middleware))
            .layer(Extension(
                Arc::new(StubIntrospector(Mutex::new(None))) as Arc<dyn TokenIntrospector>
            ))
            .layer(Extension(SessionTokenSigner::new(
                "test-secret-that-is-at-least-32-bytes-long",
                3600,
                "https://gateway.example.com",
            )))
            .layer(Extension(
                Arc::new(StubSessionStore(Mutex::new(Some(Ok(false))))) as Arc<dyn SessionStore>,
            ))
            .layer(Extension(
                Arc::new(StubMappingStore(Mutex::new(None))) as Arc<dyn IdMappingStore>
            ));
        let response = router
            .oneshot(
                Request::get("/protected")
                    .header("Cookie", format!("__Host-sso_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_token_authenticates() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(Some(Ok(
                IntrospectionResult {
                    active: true,
                    sub: Some("sub-1".into()),
                    scope: vec!["tenant:read".into()],
                    exp: None,
                },
            ))))),
            Arc::new(StubMappingStore(Mutex::new(Some(Ok(Some(
                "tenant-1".into(),
            )))))),
        );
        let response = router
            .oneshot(
                Request::get("/protected")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn inactive_token_returns_unauthorized() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(Some(Ok(
                IntrospectionResult {
                    active: false,
                    sub: Some("sub-1".into()),
                    scope: vec![],
                    exp: None,
                },
            ))))),
            Arc::new(StubMappingStore(Mutex::new(None))),
        );
        let response = router
            .oneshot(
                Request::get("/protected")
                    .header("Authorization", "Bearer invalid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_subject_returns_unauthorized() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(Some(Ok(
                IntrospectionResult {
                    active: true,
                    sub: Some("sub-1".into()),
                    scope: vec!["tenant:read".into()],
                    exp: None,
                },
            ))))),
            Arc::new(StubMappingStore(Mutex::new(Some(Ok(None))))),
        );
        let response = router
            .oneshot(
                Request::get("/protected")
                    .header("Authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
