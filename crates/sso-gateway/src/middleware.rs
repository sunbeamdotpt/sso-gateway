use axum::{
    Extension,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::agent_tokens::AgentTokenResolver;
use crate::auth::{
    ActorContext, AuthContext, SubjectBackend, SubjectType, TokenIntrospector, bearer_token,
    build_auth_context, resolve_subject,
};
use crate::db::{AGENT_STATUS_ACTIVE, ApplicationStore, IdMappingStore, SessionStore};
use crate::session_token::SessionTokenSigner;

/// Re-exported helper for RPC handlers that need stepped-up authentication.
pub use crate::auth::require_amr;

pub const TENANT_ID_HEADER: &str = "x-tenant-id";

/// Per-key token-bucket rate limiter.
///
/// One bucket per rate-limit key (usually the OAuth2 `client_id`) so a
/// runaway client cannot drain a shared bucket and starve every other
/// caller (SSO-015).
#[derive(Clone, Debug)]
pub struct RateLimiter {
    max: u32,
    per: Duration,
    state: Arc<Mutex<HashMap<String, RateLimiterState>>>,
}

#[derive(Clone, Debug)]
struct RateLimiterState {
    tokens: f64,
    last: Instant,
}

/// Hard cap on tracked buckets; a limiter is not a database.
const MAX_RATE_LIMIT_KEYS: usize = 10_000;

impl RateLimiter {
    /// Create a limiter that allows `max` requests per `per` duration for
    /// each key.
    pub fn new(max: u32, per: Duration) -> Self {
        Self {
            max,
            per,
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Attempt to consume one token for `key`. Returns `true` if the request
    /// is allowed.
    pub fn check(&self, key: &str) -> bool {
        let max = self.max as f64;
        let refill_rate = self.max as f64 / self.per.as_secs_f64();
        let mut buckets = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !buckets.contains_key(key) && buckets.len() >= MAX_RATE_LIMIT_KEYS {
            // Evict buckets that have drifted back to full; if everything is
            // saturated, start over rather than growing without bound.
            buckets.retain(|_, s| s.tokens < max);
            if buckets.len() >= MAX_RATE_LIMIT_KEYS {
                buckets.clear();
            }
        }
        let state = buckets
            .entry(key.to_string())
            .or_insert_with(|| RateLimiterState {
                tokens: max,
                last: Instant::now(),
            });
        let now = Instant::now();
        let elapsed = now.duration_since(state.last).as_secs_f64();
        state.tokens = (state.tokens + elapsed * refill_rate).min(max);
        state.last = now;
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Extract the OAuth2 `client_id` from an HTTP Basic Authorization header.
fn basic_auth_client_id(headers: &HeaderMap) -> Option<String> {
    let header = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, payload) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, _) = decoded.split_once(':')?;
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

fn query_client_id(uri: &axum::http::Uri) -> Option<String> {
    let query = uri.query()?;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == "client_id")
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.is_empty())
}

fn form_body_client_id(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)?
        .to_str()
        .ok()?;
    if !content_type.starts_with("application/x-www-form-urlencoded") {
        return None;
    }
    url::form_urlencoded::parse(body)
        .find(|(k, _)| k == "client_id")
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.is_empty())
}

/// Endpoint class used to segregate the fallback rate-limit bucket for
/// requests without an OAuth2 `client_id`.
///
/// A burst against one unauthenticated flow (e.g. discovery) must not drain
/// the bucket shared by every other unauthenticated flow (SSO-031). The set
/// is deliberately small and fixed so the key space stays bounded under
/// `MAX_RATE_LIMIT_KEYS`.
fn endpoint_class(path: &str) -> &'static str {
    if path.starts_with("/.well-known/") {
        "discovery"
    } else if path == "/oauth2/userinfo" || path == "/userinfo" {
        "userinfo"
    } else if path == "/oauth2/register" || path.starts_with("/oauth2/register/") {
        "register"
    } else if path == "/oauth2/token" {
        "token"
    } else if path == "/oauth2/introspect" {
        "introspect"
    } else if path == "/oauth2/revoke" {
        "revoke"
    } else if path == "/oauth2/device" || path.starts_with("/oauth2/device/") {
        "device"
    } else if path == "/oauth2/auth" {
        "auth"
    } else if path == "/saml" || path.starts_with("/saml/") {
        "saml"
    } else if path == "/scim" || path.starts_with("/scim/") {
        "scim"
    } else if path == "/self-service" || path.starts_with("/self-service/") {
        "self-service"
    } else if path == "/callbacks" || path.starts_with("/callbacks/") {
        "callbacks"
    } else if path == "/health" || path.starts_with("/health/") {
        "health"
    } else {
        "other"
    }
}

/// Reject requests with `429 Too Many Requests` when the key's bucket is empty.
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_string();
    // These routes already sit behind a 1 MiB DefaultBodyLimit, so buffering
    // the body to sniff a form-encoded client_id is bounded.
    let body = match axum::body::to_bytes(body, 1_048_576).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let key = match basic_auth_client_id(&parts.headers)
        .or_else(|| query_client_id(&parts.uri))
        .or_else(|| form_body_client_id(&parts.headers, &body))
    {
        Some(client_id) => client_id,
        None => format!("global:{}", endpoint_class(&path)),
    };
    let request = Request::from_parts(parts, Body::from(body));
    if limiter.check(&key) {
        next.run(request).await
    } else {
        // Log the bucket key and path only — never tokens, secrets, or
        // Authorization headers — so a drainer is identifiable from prod
        // logs running at RUST_LOG=warn (SSO-031).
        tracing::warn!(rate_limit_key = %key, path = %path, "rate limit exceeded");
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
        // RFC 7591 dynamic client registration is open (with a scope ceiling
        // enforced by the handler); introspection authenticates either with
        // client credentials (handled inside) or an opportunistic bearer.
        "/oauth2/register" | "/oauth2/introspect" => true,
        "/saml/metadata" | "/saml/acs" | "/saml/sso" => true,
        "/callbacks/oidc" | "/callbacks/oauth2" => true,
        "/scim/v2/ServiceProviderConfig" | "/scim/v2/ResourceTypes" | "/scim/v2/Schemas" => true,
        // Kratos email links (recovery/verification) land here and are
        // bounced to the branded surface; they authenticate via the token in
        // the link itself.
        "/self-service/recovery" | "/self-service/verification" => true,
        "/health" | "/health/ready" | "/health/live" => true,
        // DCR client self-delete authenticates with the client's own Basic
        // credentials inside the handler (SSO-031).
        _ => path.starts_with("/oauth2/device/") || path.starts_with("/oauth2/register/"),
    }
}

const SESSION_COOKIE_NAME: &str = "__Host-sso_session";

#[allow(clippy::too_many_arguments)]
pub async fn auth_middleware(
    Extension(introspector): Extension<Arc<dyn TokenIntrospector>>,
    Extension(mappings): Extension<Arc<dyn IdMappingStore>>,
    Extension(session_signer): Extension<SessionTokenSigner>,
    Extension(session_store): Extension<Arc<dyn SessionStore>>,
    applications: Option<Extension<Arc<dyn ApplicationStore>>>,
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
    if is_browser_path {
        return next.run(request).await;
    }
    // Public paths are reachable anonymously (their handlers do protocol-level
    // authentication). OAuth2 introspection and dynamic client registration
    // also serve bearer-authenticated callers (admin introspection; DCR
    // mapping under the caller's tenant), so a presented Bearer token is
    // authenticated there and an invalid one rejects rather than falling
    // through as anonymous. On every other public path the bearer token is
    // the protocol credential itself (e.g. userinfo) and must reach the
    // handler untouched — middleware subject resolution would reject valid
    // tokens whose subjects have no gateway mapping.
    if is_public_path(path)
        && (!matches!(path, "/oauth2/introspect" | "/oauth2/register")
            || bearer_token(request.headers()).is_none())
    {
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
            let target_tenant = resolve_target_tenant(
                &ctx,
                request.headers(),
                applications.as_ref().map(|Extension(a)| a.as_ref()),
            )
            .await;
            request.extensions_mut().insert(TenantId(target_tenant));
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

async fn resolve_target_tenant(
    ctx: &AuthContext,
    headers: &HeaderMap,
    applications: Option<&dyn ApplicationStore>,
) -> String {
    if ctx.subject_type != SubjectType::Client {
        return ctx.tenant_id.clone();
    }
    let header_value = match headers.get(TENANT_ID_HEADER).and_then(|v| v.to_str().ok()) {
        Some(v) => v,
        None => return ctx.tenant_id.clone(),
    };
    if ulid::Ulid::from_string(header_value).is_err() {
        tracing::debug!(%header_value, "ignoring malformed x-tenant-id header");
        return ctx.tenant_id.clone();
    }
    let applications = match applications {
        Some(a) => a,
        None => return ctx.tenant_id.clone(),
    };
    match applications.get_by_public_id(&ctx.subject).await {
        Ok(row) if row.cross_tenant => {
            tracing::debug!(
                subject = %ctx.subject,
                home_tenant = %ctx.tenant_id,
                target_tenant = %header_value,
                "cross-tenant header honored"
            );
            header_value.to_string()
        }
        Ok(_) => {
            tracing::debug!(
                subject = %ctx.subject,
                header_value = %header_value,
                "ignoring x-tenant-id for client without cross_tenant flag"
            );
            ctx.tenant_id.clone()
        }
        Err(err) => {
            tracing::warn!(
                %err,
                subject = %ctx.subject,
                header_value = %header_value,
                "ignoring x-tenant-id because application lookup failed"
            );
            ctx.tenant_id.clone()
        }
    }
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
        tracing::warn!(%err, "session cookie verification failed");
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

    // Infra faults (Hydra unreachable, cache/DB errors) must not impersonate
    // bad tokens: surface them as 5xx so callers can retry and monitors can
    // tell them apart from genuine rejections (SSO-024).
    let introspection = introspector.introspect(token).await.map_err(|err| {
        tracing::warn!(%err, "token introspection failed");
        match err {
            crate::auth::AuthError::IntrospectionFailed(_) => {
                Box::new(auth_error(StatusCode::SERVICE_UNAVAILABLE))
            }
            crate::auth::AuthError::Database(_) => {
                Box::new(auth_error(StatusCode::INTERNAL_SERVER_ERROR))
            }
            _ => Box::new(auth_error(StatusCode::UNAUTHORIZED)),
        }
    })?;

    if !introspection.active {
        tracing::warn!("introspected token is inactive");
        return Err(Box::new(auth_error(StatusCode::UNAUTHORIZED)));
    }

    // An active introspection without a subject is a broken upstream
    // response, not a bad token.
    let subject = introspection.sub.ok_or_else(|| {
        tracing::warn!("introspection response missing subject");
        Box::new(auth_error(StatusCode::INTERNAL_SERVER_ERROR))
    })?;

    let (tenant_id, public_subject, backend) =
        resolve_subject(mappings, &subject).await.map_err(|err| {
            tracing::warn!(%err, "failed to resolve subject");
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
    let message = match status {
        StatusCode::INTERNAL_SERVER_ERROR => "internal server error",
        StatusCode::SERVICE_UNAVAILABLE => "service unavailable",
        _ => "unauthorized",
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
    let auth_tenant_id = request
        .extensions()
        .get::<AuthContext>()
        .map(|c| c.tenant_id.clone());
    let target_tenant_id = request.extensions().get::<TenantId>().map(|t| t.0.clone());
    // Tenant ID is never taken from x-tenant-id for unauthenticated requests;
    // that would let arbitrary callers spoof the audit tenant label.
    let tenant_id = auth_tenant_id.clone();
    let cross_tenant = match (&auth_tenant_id, &target_tenant_id) {
        (Some(auth), Some(target)) => auth != target,
        _ => false,
    };
    let target_tenant = if cross_tenant {
        target_tenant_id.as_deref()
    } else {
        None
    };
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
        target_tenant = target_tenant,
        cross_tenant = cross_tenant,
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
    use crate::db::{ApplicationStore, MemoryApplicationStore};
    use crate::session_token::SessionTokenSigner;
    use axum::{
        Extension, Router, body::Body, http::Request, middleware::from_fn,
        middleware::from_fn_with_state, routing::get,
    };
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

    /// Handler echoing the resolved target tenant for cross-tenant routing assertions.
    async fn tenant_handler(Extension(TenantId(tenant_id)): Extension<TenantId>) -> String {
        tenant_id
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
            .route("/oauth2/register", get(ok_handler))
            .route("/oauth2/introspect", get(ctx_handler))
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
        assert!(is_public_path("/oauth2/register"));
        assert!(is_public_path("/oauth2/register/01JEXAMPLECLIENTID000000"));
        assert!(is_public_path("/oauth2/introspect"));
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
    async fn public_register_path_bypasses_auth_when_anonymous() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(None))),
            no_mappings(),
        );
        let response = router
            .oneshot(Request::get("/oauth2/register").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// A Bearer token on a public path is authenticated opportunistically: a
    /// valid token authenticates and the handler sees the AuthContext.
    #[tokio::test]
    async fn public_path_with_valid_bearer_authenticates_opportunistically() {
        let router = test_router(
            active_introspector("hydra-client-1"),
            hydra_mappings("tenant-1"),
        );
        let response = router
            .oneshot(
                Request::get("/oauth2/introspect")
                    .header("Authorization", "Bearer some-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), "pub-sub-1|client|");
    }

    /// An invalid Bearer token on a public path rejects instead of falling
    /// through as an anonymous request.
    #[tokio::test]
    async fn public_path_with_invalid_bearer_rejects() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(None))),
            no_mappings(),
        );
        let response = router
            .oneshot(
                Request::get("/oauth2/introspect")
                    .header("Authorization", "Bearer bad-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A valid Bearer token on /oauth2/register authenticates opportunistically
    /// so the DCR handler can map the client under the caller's tenant.
    #[tokio::test]
    async fn public_register_path_with_valid_bearer_authenticates() {
        let router = test_router(
            active_introspector("hydra-client-1"),
            hydra_mappings("tenant-1"),
        );
        let response = router
            .oneshot(
                Request::get("/oauth2/register")
                    .header("Authorization", "Bearer some-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// An invalid Bearer token on /oauth2/register rejects instead of falling
    /// through to anonymous registration.
    #[tokio::test]
    async fn public_register_path_with_invalid_bearer_rejects() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(None))),
            no_mappings(),
        );
        let response = router
            .oneshot(
                Request::get("/oauth2/register")
                    .header("Authorization", "Bearer bad-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // -----------------------------------------------------------------------
    // Introspection error mapping (SSO-024): infra faults must surface as
    // 5xx instead of impersonating bad tokens with a 401.
    // -----------------------------------------------------------------------

    fn bearer_request(path: &str) -> Request<Body> {
        Request::get(path)
            .header("Authorization", "Bearer some-token")
            .body(Body::empty())
            .unwrap()
    }

    /// A Hydra fault surfaces as 503 so callers can retry.
    #[tokio::test]
    async fn introspection_hydra_fault_returns_503() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(Some(Err(
                crate::auth::AuthError::IntrospectionFailed(
                    sso_ory_client::error::OryClientError::Ory {
                        status: 502,
                        message: "bad gateway".into(),
                    },
                ),
            ))))),
            no_mappings(),
        );
        let response = router.oneshot(bearer_request("/protected")).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A database fault during introspection surfaces as 500.
    #[tokio::test]
    async fn introspection_database_fault_returns_500() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(Some(Err(
                crate::auth::AuthError::Database(crate::db::DbError::Sqlx(sqlx::Error::RowNotFound)),
            ))))),
            no_mappings(),
        );
        let response = router.oneshot(bearer_request("/protected")).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// A genuinely inactive token still returns 401.
    #[tokio::test]
    async fn inactive_token_returns_401() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(Some(Ok(IntrospectionResult {
                active: false,
                sub: None,
                scope: vec![],
                exp: None,
                authentication_methods: vec![],
            }))))),
            no_mappings(),
        );
        let response = router.oneshot(bearer_request("/protected")).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// An active introspection without a subject is a broken upstream
    /// response, not a bad token: 500.
    #[tokio::test]
    async fn active_introspection_missing_subject_returns_500() {
        let router = test_router(
            Arc::new(StubIntrospector(Mutex::new(Some(Ok(IntrospectionResult {
                active: true,
                sub: None,
                scope: vec![],
                exp: None,
                authentication_methods: vec![],
            }))))),
            no_mappings(),
        );
        let response = router.oneshot(bearer_request("/protected")).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // Keyed rate limiting (SSO-015)
    // -----------------------------------------------------------------------

    async fn echo_body(body: String) -> String {
        body
    }

    fn rate_limit_router(limiter: Arc<RateLimiter>) -> Router {
        Router::new()
            .route("/limited", get(ok_handler).post(echo_body))
            .route("/.well-known/openid-configuration", get(ok_handler))
            .route("/.well-known/jwks.json", get(ok_handler))
            .route("/oauth2/userinfo", get(ok_handler))
            .layer(from_fn_with_state(limiter, rate_limit_middleware))
    }

    fn basic_auth_value(client_id: &str) -> String {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{client_id}:secret"),
        );
        format!("Basic {encoded}")
    }

    #[tokio::test]
    async fn rate_limit_keys_on_form_body_client_id_and_preserves_body() {
        let router = rate_limit_router(Arc::new(RateLimiter::new(1, Duration::from_secs(60))));
        let payload = "client_id=form-client&grant_type=client_credentials";
        let response = router
            .clone()
            .oneshot(
                Request::post("/limited")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // The downstream handler still reads the full body.
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), payload);

        // Second request from the same client exhausts its bucket...
        let response = router
            .clone()
            .oneshot(
                Request::post("/limited")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // ...while a different client_id has its own bucket.
        let response = router
            .oneshot(
                Request::post("/limited")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "client_id=other-client&grant_type=client_credentials",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rate_limit_buckets_are_independent_per_basic_auth_client() {
        let router = rate_limit_router(Arc::new(RateLimiter::new(1, Duration::from_secs(60))));
        let response = router
            .clone()
            .oneshot(
                Request::get("/limited")
                    .header("Authorization", basic_auth_value("client-a"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router
            .clone()
            .oneshot(
                Request::get("/limited")
                    .header("Authorization", basic_auth_value("client-a"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = router
            .oneshot(
                Request::get("/limited")
                    .header("Authorization", basic_auth_value("client-b"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rate_limit_keys_on_query_client_id() {
        let router = rate_limit_router(Arc::new(RateLimiter::new(1, Duration::from_secs(60))));
        let response = router
            .clone()
            .oneshot(
                Request::get("/limited?client_id=query-client")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router
            .clone()
            .oneshot(
                Request::get("/limited?client_id=query-client")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = router
            .oneshot(Request::get("/limited").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn endpoint_class_maps_paths_to_fixed_set() {
        assert_eq!(endpoint_class("/.well-known/openid-configuration"), "discovery");
        assert_eq!(endpoint_class("/.well-known/jwks.json"), "discovery");
        assert_eq!(endpoint_class("/oauth2/userinfo"), "userinfo");
        assert_eq!(endpoint_class("/userinfo"), "userinfo");
        assert_eq!(endpoint_class("/oauth2/register"), "register");
        assert_eq!(endpoint_class("/oauth2/register/abc"), "register");
        assert_eq!(endpoint_class("/oauth2/token"), "token");
        assert_eq!(endpoint_class("/oauth2/introspect"), "introspect");
        assert_eq!(endpoint_class("/oauth2/revoke"), "revoke");
        assert_eq!(endpoint_class("/oauth2/device/auth"), "device");
        assert_eq!(endpoint_class("/oauth2/auth"), "auth");
        assert_eq!(endpoint_class("/saml/metadata"), "saml");
        assert_eq!(endpoint_class("/scim/v2/Users"), "scim");
        assert_eq!(endpoint_class("/self-service/recovery"), "self-service");
        assert_eq!(endpoint_class("/callbacks/oidc"), "callbacks");
        assert_eq!(endpoint_class("/health"), "health");
        assert_eq!(endpoint_class("/health/ready"), "health");
        assert_eq!(endpoint_class("/limited"), "other");
        assert_eq!(endpoint_class("/iam/v1/tenants"), "other");
    }

    /// Without a client_id, the fallback bucket is keyed per endpoint class:
    /// draining one class (here `other`) must not starve another (`discovery`).
    #[tokio::test]
    async fn rate_limit_falls_back_to_per_class_global_bucket() {
        let router = rate_limit_router(Arc::new(RateLimiter::new(2, Duration::from_secs(60))));
        for i in 0..2 {
            let response = router
                .clone()
                .oneshot(Request::get("/limited").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "request {i} should pass");
        }
        let response = router
            .clone()
            .oneshot(Request::get("/limited").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        // The discovery class bucket is untouched by the `other` burst.
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

    /// Segregation (SSO-031): a burst draining the `discovery` bucket does
    /// not 429 `userinfo`, and a burst draining `userinfo` does not 429
    /// `discovery`.
    #[tokio::test]
    async fn rate_limit_global_buckets_are_segregated_by_endpoint_class() {
        // Drain discovery; userinfo must stay available.
        let router = rate_limit_router(Arc::new(RateLimiter::new(1, Duration::from_secs(60))));
        let response = router
            .clone()
            .oneshot(
                Request::get("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router
            .clone()
            .oneshot(
                Request::get("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = router
            .oneshot(
                Request::get("/oauth2/userinfo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Drain userinfo; discovery must stay available.
        let router = rate_limit_router(Arc::new(RateLimiter::new(1, Duration::from_secs(60))));
        let response = router
            .clone()
            .oneshot(
                Request::get("/oauth2/userinfo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router
            .clone()
            .oneshot(
                Request::get("/oauth2/userinfo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
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

    /// Paths within one endpoint class share a single bucket:
    /// `/.well-known/openid-configuration` and `/.well-known/jwks.json` both
    /// draw from `global:discovery`.
    #[tokio::test]
    async fn rate_limit_global_bucket_is_shared_within_endpoint_class() {
        let router = rate_limit_router(Arc::new(RateLimiter::new(2, Duration::from_secs(60))));
        let response = router
            .clone()
            .oneshot(
                Request::get("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router
            .clone()
            .oneshot(
                Request::get("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // Both discovery paths together exhaust the shared bucket.
        let response = router
            .clone()
            .oneshot(
                Request::get("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = router
            .oneshot(
                Request::get("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// A client_id-keyed request has its own bucket, independent of every
    /// `global:*` fallback bucket.
    #[tokio::test]
    async fn rate_limit_client_id_buckets_are_independent_of_global_buckets() {
        let router = rate_limit_router(Arc::new(RateLimiter::new(1, Duration::from_secs(60))));
        // Drain the `global:other` bucket with client_id-less requests.
        let response = router
            .clone()
            .oneshot(Request::get("/limited").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router
            .clone()
            .oneshot(Request::get("/limited").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        // A client_id-keyed request to the same path still passes.
        let response = router
            .clone()
            .oneshot(
                Request::get("/limited?client_id=query-client")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // ...and its own bucket is the one that drains.
        let response = router
            .clone()
            .oneshot(
                Request::get("/limited?client_id=query-client")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        // The client_id burst never touched the `global:discovery` bucket.
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

    /// On every other public path the bearer token is the protocol
    /// credential itself (e.g. userinfo) and must reach the handler
    /// untouched — even when its subject has no gateway mapping, which the
    /// middleware's subject resolution would otherwise reject with a 401.
    #[tokio::test]
    async fn public_path_with_unmapped_bearer_passes_through() {
        let router = test_router(active_introspector("unmapped-subject"), no_mappings());
        let response = router
            .oneshot(
                Request::get("/oauth2/auth")
                    .header("Authorization", "Bearer protocol-token")
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

    fn client_introspector(sub: &str) -> Arc<dyn TokenIntrospector> {
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

    fn cross_tenant_router(applications: Arc<dyn ApplicationStore>) -> Router {
        test_router_with_resolver(
            client_introspector("hydra-client-1"),
            hydra_mappings("tenant-1"),
            None,
        )
        .layer(Extension(applications))
    }

    async fn ctx_body_with_header(router: Router, header_value: &str) -> (StatusCode, String) {
        let response = router
            .oneshot(
                Request::get("/ctx")
                    .header("Authorization", "Bearer some-token")
                    .header("x-tenant-id", header_value)
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

    // -----------------------------------------------------------------------
    // Cross-tenant x-tenant-id header gate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cross_tenant_header_overrides_tenant_for_flagged_client() {
        let apps = Arc::new(MemoryApplicationStore::default());
        apps.create("tenant-1", "pub-sub-1", true).await.unwrap();
        let target_tenant = ulid::Ulid::new().to_string();

        let router = cross_tenant_router(apps);
        let (status, body) = ctx_body_with_header(router, &target_tenant).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "pub-sub-1|client|");
    }

    #[tokio::test]
    async fn cross_tenant_header_overrides_resolved_tenant_for_flagged_client() {
        let apps: Arc<dyn ApplicationStore> = Arc::new(MemoryApplicationStore::default());
        apps.create("tenant-1", "pub-sub-1", true).await.unwrap();
        let target_tenant = ulid::Ulid::new().to_string();

        let router = Router::new()
            .route("/tenant", get(tenant_handler))
            .layer(from_fn(auth_middleware))
            .layer(Extension(client_introspector("hydra-client-1")))
            .layer(Extension(SessionTokenSigner::new(
                "test-secret-that-is-at-least-32-bytes-long",
                3600,
                "https://gateway.example.com",
            )))
            .layer(Extension(
                Arc::new(StubSessionStore(Mutex::new(Some(Ok(true))))) as Arc<dyn SessionStore>,
            ))
            .layer(Extension(hydra_mappings("tenant-1")))
            .layer(Extension(apps));

        let response = router
            .oneshot(
                Request::get("/tenant")
                    .header("Authorization", "Bearer some-token")
                    .header("x-tenant-id", &target_tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), target_tenant);
    }

    #[tokio::test]
    async fn cross_tenant_header_ignored_for_user() {
        let apps = Arc::new(MemoryApplicationStore::default());
        apps.create("tenant-1", "pub-sub-1", true).await.unwrap();
        let target_tenant = ulid::Ulid::new().to_string();

        let router = test_router(
            client_introspector("kratos-identity-1"),
            Arc::new(StubMappingStore {
                hydra: None,
                kratos: Some("tenant-1".into()),
            }),
        )
        .layer(Extension(apps));

        let (status, body) = ctx_body_with_header(router, &target_tenant).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "pub-sub-1|user|");
    }

    #[tokio::test]
    async fn cross_tenant_header_ignored_for_agent() {
        let apps = Arc::new(MemoryApplicationStore::default());
        apps.create("tenant-1", "pub-sub-1", true).await.unwrap();
        let target_tenant = ulid::Ulid::new().to_string();

        let resolver = Arc::new(StubAgentResolver {
            status_result: Mutex::new(Some(Ok(Some("active".into())))),
            ..Default::default()
        });
        let router = test_router_with_resolver(
            client_introspector("hydra-client-1"),
            hydra_mappings("tenant-1"),
            Some(resolver),
        )
        .layer(Extension(apps));

        let (status, body) = ctx_body_with_header(router, &target_tenant).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "pub-sub-1|agent|");
    }

    #[tokio::test]
    async fn cross_tenant_header_ignored_for_unflagged_client() {
        let apps = Arc::new(MemoryApplicationStore::default());
        apps.create("tenant-1", "pub-sub-1", false).await.unwrap();
        let target_tenant = ulid::Ulid::new().to_string();

        let router = cross_tenant_router(apps);
        let (status, body) = ctx_body_with_header(router, &target_tenant).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "pub-sub-1|client|");
    }

    #[tokio::test]
    async fn cross_tenant_header_ignored_when_application_row_missing() {
        // This is the historical bootstrap-client bug: a service token whose
        // subject has no applications row must never route via x-tenant-id,
        // even when the header is a valid ULID.
        let apps: Arc<dyn ApplicationStore> = Arc::new(MemoryApplicationStore::default());
        let target_tenant = ulid::Ulid::new().to_string();

        let router = Router::new()
            .route("/tenant", get(tenant_handler))
            .layer(from_fn(auth_middleware))
            .layer(Extension(client_introspector("hydra-client-1")))
            .layer(Extension(SessionTokenSigner::new(
                "test-secret-that-is-at-least-32-bytes-long",
                3600,
                "https://gateway.example.com",
            )))
            .layer(Extension(
                Arc::new(StubSessionStore(Mutex::new(Some(Ok(true))))) as Arc<dyn SessionStore>,
            ))
            .layer(Extension(hydra_mappings("tenant-1")))
            .layer(Extension(apps));

        let response = router
            .oneshot(
                Request::get("/tenant")
                    .header("Authorization", "Bearer some-token")
                    .header("x-tenant-id", &target_tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), "tenant-1");
    }

    #[tokio::test]
    async fn cross_tenant_header_ignored_when_value_is_not_ulid() {
        let apps = Arc::new(MemoryApplicationStore::default());
        apps.create("tenant-1", "pub-sub-1", true).await.unwrap();

        let router = cross_tenant_router(apps);
        let (status, body) = ctx_body_with_header(router, "not-a-ulid").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "pub-sub-1|client|");
    }

    #[tokio::test]
    async fn unauthenticated_request_does_not_use_header_in_audit_tenant_id() {
        let layer = CaptureLayer::default();
        let events = layer.events.clone();
        let _guard = tracing_subscriber::registry().with(layer).set_default();

        let app = Router::new()
            .route("/protected", get(|| async { StatusCode::UNAUTHORIZED }))
            .layer(from_fn(audit_middleware));

        let response = app
            .oneshot(
                Request::get("/protected")
                    .header("x-tenant-id", "tenant-spoof")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let audit_events: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.target == "sso_gateway::audit")
            .cloned()
            .collect();
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].fields.get("tenant_id"), None);
        assert_eq!(audit_events[0].fields.get("target_tenant"), None);
    }

    #[tokio::test]
    async fn audit_middleware_logs_cross_tenant_override() {
        let layer = CaptureLayer::default();
        let events = layer.events.clone();
        let _guard = tracing_subscriber::registry().with(layer).set_default();

        let app = Router::new()
            .route("/protected", get(ok_handler))
            .layer(from_fn(audit_middleware))
            .layer(Extension(AuthContext {
                tenant_id: "home-tenant".into(),
                subject: "sub-1".into(),
                subject_type: SubjectType::Client,
                actor: None,
                scopes: vec![],
                token_hash: "hash".into(),
                authentication_methods: Vec::new(),
            }))
            .layer(Extension(TenantId("target-tenant".into())));

        let response = app
            .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
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
        assert_eq!(fields.get("tenant_id"), Some(&"home-tenant".to_string()));
        assert_eq!(
            fields.get("target_tenant"),
            Some(&"target-tenant".to_string())
        );
        assert_eq!(fields.get("cross_tenant"), Some(&"true".to_string()));
    }
}
