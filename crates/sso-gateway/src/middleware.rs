use axum::{
    Extension,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::agent_tokens::AgentTokenResolver;
use crate::auth::{
    ActorContext, AuthContext, SubjectBackend, SubjectType, TokenIntrospector, bearer_token,
    build_auth_context, resolve_subject,
};
use crate::db::{AGENT_STATUS_ACTIVE, IdMappingStore, SessionStore};
use crate::session_token::SessionTokenSigner;

/// Re-exported helper for RPC handlers that need stepped-up authentication.
pub use crate::auth::require_amr;

pub const TENANT_ID_HEADER: &str = "x-tenant-id";

/// Simple token-bucket rate limiter.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    max: u32,
    per: Duration,
    state: Arc<Mutex<RateLimiterState>>,
}

#[derive(Clone, Debug)]
struct RateLimiterState {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    /// Create a limiter that allows `max` requests per `per` duration.
    pub fn new(max: u32, per: Duration) -> Self {
        Self {
            max,
            per,
            state: Arc::new(Mutex::new(RateLimiterState {
                tokens: max as f64,
                last: Instant::now(),
            })),
        }
    }

    /// Attempt to consume one token. Returns `true` if the request is allowed.
    pub fn check(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let elapsed = now.duration_since(state.last).as_secs_f64();
        let refill = elapsed * (self.max as f64 / self.per.as_secs_f64());
        state.tokens = (state.tokens + refill).min(self.max as f64);
        state.last = now;
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Reject requests with `429 Too Many Requests` when the rate limiter is empty.
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    if limiter.check() {
        next.run(request).await
    } else {
        StatusCode::TOO_MANY_REQUESTS.into_response()
    }
}

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
        "/oauth2/auth" | "/oauth2/token" | "/oauth2/revoke" | "/oauth2/userinfo" | "/userinfo" => {
            true
        }
        "/saml/metadata" | "/saml/acs" | "/saml/sso" => true,
        "/callbacks/oidc" | "/callbacks/oauth2" => true,
        "/scim/v2/ServiceProviderConfig" | "/scim/v2/ResourceTypes" | "/scim/v2/Schemas" => true,
        // Kratos email links (recovery/verification) land here and are
        // bounced to the branded surface; they authenticate via the token in
        // the link itself.
        "/self-service/recovery" | "/self-service/verification" => true,
        "/health" | "/health/ready" | "/health/live" => true,
        _ => path.starts_with("/oauth2/device/"),
    }
}

const SESSION_COOKIE_NAME: &str = "__Host-sso_session";

#[allow(clippy::too_many_arguments)]
pub async fn auth_middleware(
    Extension(introspector): Extension<Arc<dyn TokenIntrospector>>,
    Extension(mappings): Extension<Arc<dyn IdMappingStore>>,
    Extension(session_signer): Extension<SessionTokenSigner>,
    Extension(session_store): Extension<Arc<dyn SessionStore>>,
    agent_resolver: Option<Extension<Arc<dyn AgentTokenResolver>>>,
    self_service_paths: Option<Extension<Arc<crate::config::SelfServicePaths>>>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    // Branded browser self-service routes carry Kratos cookies, not bearer
    // tokens; the proxy and Kratos perform the session checks.
    let is_browser_path = self_service_paths
        .as_ref()
        .is_some_and(|Extension(paths)| paths.is_browser_path(path));
    if is_public_path(path) || is_browser_path {
        return next.run(request).await;
    }

    let auth_result = if let Some(token) = bearer_token(request.headers()) {
        authenticate_bearer_token(
            introspector.as_ref(),
            mappings.as_ref(),
            agent_resolver.as_ref().map(|Extension(r)| r.as_ref()),
            &token,
        )
        .await
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
    // HTTP/2 clients may split cookies across multiple Cookie header fields
    // (RFC 7540 §8.1.2.5); receivers are required to reassemble them with
    // "; " before parsing.
    let joined = headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    if joined.is_empty() {
        return None;
    }
    joined.split(';').find_map(|cookie| {
        let (name, value) = cookie.trim().split_once('=')?;
        if name == SESSION_COOKIE_NAME {
            Some(value.to_string())
        } else {
            None
        }
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
        SubjectType::User,
        None,
        vec![],
        vec![],
        &cookie,
    ))
}

async fn authenticate_bearer_token(
    introspector: &dyn TokenIntrospector,
    mappings: &dyn IdMappingStore,
    agent_resolver: Option<&dyn AgentTokenResolver>,
    token: &str,
) -> Result<AuthContext, Box<Response>> {
    // Agent act-tokens are opaque and unknown to Hydra, so they must be
    // resolved before falling through to Hydra introspection.
    if let Some(resolver) = agent_resolver {
        match resolver.resolve_act_token(token).await {
            Ok(Some(resolution)) => {
                return Ok(build_auth_context(
                    resolution.tenant_id,
                    resolution.user_identity_id,
                    SubjectType::User,
                    Some(ActorContext {
                        agent_id: resolution.agent_id,
                        delegation_id: resolution.delegation_id,
                    }),
                    resolution.scopes,
                    vec![],
                    token,
                ));
            }
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(%err, "agent act-token resolution failed");
                return Err(Box::new(auth_error(StatusCode::INTERNAL_SERVER_ERROR)));
            }
        }
    }

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

    let (tenant_id, public_subject, backend) =
        resolve_subject(mappings, &subject).await.map_err(|err| {
            tracing::debug!(%err, "failed to resolve subject");
            match err {
                crate::auth::AuthError::UnknownSubject => {
                    Box::new(auth_error(StatusCode::UNAUTHORIZED))
                }
                _ => Box::new(auth_error(StatusCode::INTERNAL_SERVER_ERROR)),
            }
        })?;

    let subject_type = match backend {
        SubjectBackend::Kratos => SubjectType::User,
        SubjectBackend::Hydra => {
            // A Hydra-backed subject is either a registered agent or a plain
            // machine client. A disabled agent is rejected here: the big red
            // button also kills the agent's own client-credentials tokens.
            match agent_resolver {
                Some(resolver) => match resolver.agent_status(&public_subject).await {
                    Ok(Some(status)) if status != AGENT_STATUS_ACTIVE => {
                        return Err(Box::new(auth_error(StatusCode::UNAUTHORIZED)));
                    }
                    Ok(Some(_)) => SubjectType::Agent,
                    Ok(None) => SubjectType::Client,
                    Err(err) => {
                        tracing::warn!(%err, "agent status lookup failed");
                        return Err(Box::new(auth_error(StatusCode::INTERNAL_SERVER_ERROR)));
                    }
                },
                None => SubjectType::Client,
            }
        }
    };

    Ok(build_auth_context(
        tenant_id,
        public_subject,
        subject_type,
        None,
        introspection.scope,
        introspection.authentication_methods,
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

/// Best-effort audit logging middleware.
///
/// Captures the HTTP method, path, resolved tenant, authenticated actor, and
/// response status, and emits a structured log event to the standard log
/// stream tagged with `sso_gateway::audit`.
pub async fn audit_middleware(request: Request, next: Next) -> Response {
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
    let subject_type = request
        .extensions()
        .get::<AuthContext>()
        .map(|c| c.subject_type.as_str());
    let agent = request
        .extensions()
        .get::<AuthContext>()
        .and_then(|c| c.actor.as_ref().map(|a| a.agent_id.clone()));
    let method = request.method().to_string();
    let resource = request.uri().path().to_string();

    let response = next.run(request).await;

    let outcome = if response.status().is_success() {
        "success"
    } else {
        "failure"
    };

    tracing::info!(
        target: "sso_gateway::audit",
        tenant_id = tenant_id.as_deref(),
        actor = actor.as_deref(),
        subject_type = subject_type,
        agent = agent.as_deref(),
        action = method.as_str(),
        resource = resource.as_str(),
        outcome = outcome,
        status = response.status().as_u16(),
        "audit event"
    );

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
    use tracing_subscriber::prelude::*;

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

    /// Backend-aware mapping stub: each field is the tenant the corresponding
    /// backend resolves for any subject.
    struct StubMappingStore {
        hydra: Option<String>,
        kratos: Option<String>,
    }

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
            backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, crate::db::DbError> {
            match backend {
                "hydra" => Ok(self.hydra.clone()),
                _ => Ok(self.kratos.clone()),
            }
        }
    }

    #[derive(Default)]
    struct StubAgentResolver {
        resolve_result:
            Mutex<Option<Result<Option<crate::agent_tokens::ActTokenResolution>, crate::db::DbError>>>,
        status_result: Mutex<Option<Result<Option<String>, crate::db::DbError>>>,
    }

    #[async_trait::async_trait]
    impl AgentTokenResolver for StubAgentResolver {
        async fn resolve_act_token(
            &self,
            _token: &str,
        ) -> Result<Option<crate::agent_tokens::ActTokenResolution>, crate::db::DbError> {
            self.resolve_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Ok(None))
        }

        async fn agent_status(
            &self,
            _agent_id: &str,
        ) -> Result<Option<String>, crate::db::DbError> {
            self.status_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Ok(None))
        }
    }

    fn no_mappings() -> Arc<dyn IdMappingStore> {
        Arc::new(StubMappingStore {
            hydra: None,
            kratos: None,
        })
    }

    fn hydra_mappings(tenant: &str) -> Arc<dyn IdMappingStore> {
        Arc::new(StubMappingStore {
            hydra: Some(tenant.to_string()),
            kratos: None,
        })
    }

    async fn ok_handler() -> &'static str {
        "ok"
    }

    /// Handler echoing the resolved AuthContext for classification assertions.
    async fn ctx_handler(Extension(ctx): Extension<AuthContext>) -> String {
        format!(
            "{}|{}|{}",
            ctx.subject,
            ctx.subject_type.as_str(),
            ctx.actor.map(|a| a.agent_id).unwrap_or_default()
        )
    }

    fn test_router(
        introspector: Arc<dyn TokenIntrospector>,
        mappings: Arc<dyn IdMappingStore>,
    ) -> Router {
        test_router_with_resolver(introspector, mappings, None)
    }

    fn test_router_with_resolver(
        introspector: Arc<dyn TokenIntrospector>,
        mappings: Arc<dyn IdMappingStore>,
        resolver: Option<Arc<dyn AgentTokenResolver>>,
    ) -> Router {
        let mut router = Router::new()
            .route("/protected", get(ok_handler))
            .route("/ctx", get(ctx_handler))
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
            .layer(Extension(mappings));
        if let Some(resolver) = resolver {
            router = router.layer(Extension(resolver));
        }
        router
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
        assert!(is_public_path("/userinfo"));
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
        assert!(is_public_path("/self-service/recovery"));
        assert!(is_public_path("/self-service/verification"));
        assert!(!is_public_path("/.well-known/ory/webauthn.js"));
        assert!(!is_public_path("/self-service/login/browser"));
        assert!(!is_public_path("/identity/login"));
        assert!(!is_public_path("/iam/v1/tenants"));
    }

    #[tokio::test]
    async fn branded_browser_path_bypasses_auth() {
        let router = Router::new()
            .route("/identity/login", get(ok_handler))
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
                Arc::new(StubSessionStore(Mutex::new(Some(Ok(true))))) as Arc<dyn SessionStore>,
            ))
            .layer(Extension(no_mappings()))
            .layer(Extension(Arc::new(crate::config::SelfServicePaths::default())));
        let response = router
            .oneshot(
                Request::get("/identity/login?aal=aal2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn non_browser_path_still_requires_auth_with_paths_extension() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(None))),
            no_mappings(),
        )
        .layer(Extension(Arc::new(crate::config::SelfServicePaths::default())));
        let response = router
            .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn public_path_bypasses_auth() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(None))),
            no_mappings(),
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
            no_mappings(),
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
            no_mappings(),
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

    /// HTTP/2 clients may split cookies across multiple Cookie header fields
    /// (RFC 7540 §8.1.2.5); the session cookie must be found no matter which
    /// field carries it.
    #[tokio::test]
    async fn session_cookie_found_across_split_cookie_headers() {
        let signer = SessionTokenSigner::new(
            "test-secret-that-is-at-least-32-bytes-long",
            3600,
            "https://gateway.example.com",
        );
        let (token, _) = signer.issue("public-1", "tenant-1", "oidc").unwrap();
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(None))),
            no_mappings(),
        );
        let response = router
            .oneshot(
                Request::get("/protected")
                    .header("Cookie", "oauth2_authentication_csrf=csrf-value")
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
            no_mappings(),
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
            .layer(Extension(no_mappings()));
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
                    authentication_methods: vec![],
                },
            ))))),
            hydra_mappings("tenant-1"),
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
                    authentication_methods: vec![],
                },
            ))))),
            no_mappings(),
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
                    authentication_methods: vec![],
                },
            ))))),
            no_mappings(),
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

    #[derive(Default, Clone)]
    struct CaptureLayer {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    #[derive(Clone)]
    struct CapturedEvent {
        target: String,
        fields: std::collections::HashMap<String, String>,
    }

    #[derive(Default)]
    struct FieldVisitor {
        fields: std::collections::HashMap<String, String>,
    }

    impl tracing::field::Visit for FieldVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{:?}", value));
        }
    }

    impl<S> tracing_subscriber::Layer<S> for CaptureLayer
    where
        S: tracing::Subscriber,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            self.events.lock().unwrap().push(CapturedEvent {
                target: event.metadata().target().to_string(),
                fields: visitor.fields,
            });
        }
    }

    #[tokio::test]
    async fn audit_middleware_emits_structured_success_log() {
        let layer = CaptureLayer::default();
        let events = layer.events.clone();
        let _guard = tracing_subscriber::registry().with(layer).set_default();

        let app = Router::new()
            .route("/test", get(ok_handler))
            .layer(from_fn(audit_middleware));
        let response = app
            .oneshot(Request::get("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let audit_events: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.target == "sso_gateway::audit")
            .cloned()
            .collect();
        assert_eq!(audit_events.len(), 1);
        let fields = &audit_events[0].fields;
        assert_eq!(fields.get("resource"), Some(&"/test".to_string()));
        assert_eq!(fields.get("action"), Some(&"GET".to_string()));
        assert_eq!(fields.get("outcome"), Some(&"success".to_string()));
        assert_eq!(fields.get("status"), Some(&"200".to_string()));
    }

    #[tokio::test]
    async fn audit_middleware_emits_structured_failure_log_with_context() {
        let layer = CaptureLayer::default();
        let events = layer.events.clone();
        let _guard = tracing_subscriber::registry().with(layer).set_default();

        let app = Router::new()
            .route("/err", get(|| async { StatusCode::FORBIDDEN }))
            .layer(from_fn(audit_middleware))
            .layer(Extension(TenantId("tenant-42".into())))
            .layer(Extension(AuthContext {
                tenant_id: "tenant-42".into(),
                subject: "actor-7".into(),
                subject_type: SubjectType::User,
                actor: Some(crate::auth::ActorContext {
                    agent_id: "agent-9".into(),
                    delegation_id: "del-9".into(),
                }),
                scopes: vec![],
                token_hash: "hash".into(),
                authentication_methods: vec![],
            }));
        let response = app
            .oneshot(Request::get("/err").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let audit_events: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.target == "sso_gateway::audit")
            .cloned()
            .collect();
        assert_eq!(audit_events.len(), 1);
        let fields = &audit_events[0].fields;
        assert_eq!(fields.get("tenant_id"), Some(&"tenant-42".to_string()));
        assert_eq!(fields.get("actor"), Some(&"actor-7".to_string()));
        assert_eq!(fields.get("resource"), Some(&"/err".to_string()));
        assert_eq!(fields.get("action"), Some(&"GET".to_string()));
        assert_eq!(fields.get("outcome"), Some(&"failure".to_string()));
        assert_eq!(fields.get("status"), Some(&"403".to_string()));
        assert_eq!(fields.get("subject_type"), Some(&"user".to_string()));
        assert_eq!(fields.get("agent"), Some(&"agent-9".to_string()));
    }

    // -----------------------------------------------------------------------
    // Agent subject classification
    // -----------------------------------------------------------------------

    fn active_introspector(sub: &str) -> Arc<dyn TokenIntrospector> {
        Arc::new(StubIntrospector(Mutex::new(Some(Ok(
            IntrospectionResult {
                active: true,
                sub: Some(sub.to_string()),
                scope: vec!["tenant:read".into()],
                exp: None,
                authentication_methods: vec![],
            },
        )))))
    }

    async fn ctx_body(router: Router) -> (StatusCode, String) {
        let response = router
            .oneshot(
                Request::get("/ctx")
                    .header("Authorization", "Bearer some-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn act_token_authenticates_as_user_with_actor() {
        let resolver = Arc::new(StubAgentResolver {
            resolve_result: Mutex::new(Some(Ok(Some(
                crate::agent_tokens::ActTokenResolution {
                    tenant_id: "tenant-1".into(),
                    user_identity_id: "user-1".into(),
                    agent_id: "agent-1".into(),
                    delegation_id: "del-1".into(),
                    scopes: vec!["kanban:read".into()],
                    expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
                },
            )))),
            ..Default::default()
        });
        // The introspector must never be consulted for act-tokens: it holds
        // no result and would fail the request if called.
        let router = test_router_with_resolver(
            Arc::new(StubIntrospector(Mutex::new(None))),
            no_mappings(),
            Some(resolver),
        );

        let (status, body) = ctx_body(router).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "user-1|user|agent-1");
    }

    #[tokio::test]
    async fn act_token_resolution_error_fails_closed() {
        let resolver = Arc::new(StubAgentResolver {
            resolve_result: Mutex::new(Some(Err(crate::db::DbError::AgentNotFound))),
            ..Default::default()
        });
        let router = test_router_with_resolver(
            active_introspector("sub-1"),
            hydra_mappings("tenant-1"),
            Some(resolver),
        );

        let (status, _) = ctx_body(router).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn kratos_subject_classifies_as_user() {
        let router = test_router(
            active_introspector("kratos-identity-1"),
            Arc::new(StubMappingStore {
                hydra: None,
                kratos: Some("tenant-1".into()),
            }),
        );

        let (status, body) = ctx_body(router).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "pub-sub-1|user|");
    }

    #[tokio::test]
    async fn hydra_subject_with_active_agent_status_classifies_as_agent() {
        let resolver = Arc::new(StubAgentResolver {
            status_result: Mutex::new(Some(Ok(Some("active".into())))),
            ..Default::default()
        });
        let router = test_router_with_resolver(
            active_introspector("hydra-client-1"),
            hydra_mappings("tenant-1"),
            Some(resolver),
        );

        let (status, body) = ctx_body(router).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "pub-sub-1|agent|");
    }

    #[tokio::test]
    async fn hydra_subject_with_disabled_agent_status_is_rejected() {
        let resolver = Arc::new(StubAgentResolver {
            status_result: Mutex::new(Some(Ok(Some("disabled".into())))),
            ..Default::default()
        });
        let router = test_router_with_resolver(
            active_introspector("hydra-client-1"),
            hydra_mappings("tenant-1"),
            Some(resolver),
        );

        let (status, _) = ctx_body(router).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn hydra_subject_without_agent_record_classifies_as_client() {
        let resolver = Arc::new(StubAgentResolver::default());
        let router = test_router_with_resolver(
            active_introspector("hydra-client-1"),
            hydra_mappings("tenant-1"),
            Some(resolver),
        );

        let (status, body) = ctx_body(router).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "pub-sub-1|client|");
    }

    #[tokio::test]
    async fn agent_status_lookup_error_fails_closed() {
        let resolver = Arc::new(StubAgentResolver {
            status_result: Mutex::new(Some(Err(crate::db::DbError::MappingNotFound))),
            ..Default::default()
        });
        let router = test_router_with_resolver(
            active_introspector("hydra-client-1"),
            hydra_mappings("tenant-1"),
            Some(resolver),
        );

        let (status, _) = ctx_body(router).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
