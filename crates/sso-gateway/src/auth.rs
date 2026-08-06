use std::sync::Arc;

use async_trait::async_trait;
use axum::http::{HeaderMap, header::AUTHORIZATION};
use connectrpc::RequestContext;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sso_ory_client::{HydraClient, error::OryClientError};
use sunbeam_g2v::error::ServiceError;
use thiserror::Error;
use tracing::{debug, instrument, warn};

use crate::db::{DbError, IdMappingStore, TokenIntrospectionCache};

/// OAuth2 scopes used across gateway services.
pub const SCOPE_OPENID: &str = "openid";
pub const SCOPE_TENANT_ADMIN: &str = "tenant:admin";
pub const SCOPE_TENANT_READ: &str = "tenant:read";
pub const SCOPE_IDENTITY_ADMIN: &str = "identity:admin";
pub const SCOPE_IDENTITY_READ: &str = "identity:read";
pub const SCOPE_SCIM_ADMIN: &str = "scim:admin";
pub const SCOPE_SCIM_READ: &str = "scim:read";
pub const SCOPE_PERMISSION_ADMIN: &str = "permission:admin";
pub const SCOPE_PERMISSION_READ: &str = "permission:read";
pub const SCOPE_APPLICATION_ADMIN: &str = "application:admin";
pub const SCOPE_APPLICATION_READ: &str = "application:read";
pub const SCOPE_AGENT_ADMIN: &str = "agent:admin";
pub const SCOPE_AGENT_READ: &str = "agent:read";
/// Allows an agent to mint on-behalf-of act-tokens against its delegations.
pub const SCOPE_AGENT_ACT: &str = "agent:act";

/// Every scope the gateway recognizes, for validating client/agent scope sets.
pub const KNOWN_SCOPES: &[&str] = &[
    SCOPE_OPENID,
    SCOPE_TENANT_ADMIN,
    SCOPE_TENANT_READ,
    SCOPE_IDENTITY_ADMIN,
    SCOPE_IDENTITY_READ,
    SCOPE_SCIM_ADMIN,
    SCOPE_SCIM_READ,
    SCOPE_PERMISSION_ADMIN,
    SCOPE_PERMISSION_READ,
    SCOPE_APPLICATION_ADMIN,
    SCOPE_APPLICATION_READ,
    SCOPE_AGENT_ADMIN,
    SCOPE_AGENT_READ,
    SCOPE_AGENT_ACT,
];

/// What kind of identity the authenticated subject is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectType {
    /// A human user (a Kratos-backed identity). This is also the subject type
    /// of a delegated agent act-token, whose `sub` is the delegating user.
    User,
    /// A registered agent acting autonomously with its own client credentials.
    Agent,
    /// A machine-to-machine OAuth2 client credential that is not a registered
    /// agent.
    Client,
}

impl SubjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SubjectType::User => "user",
            SubjectType::Agent => "agent",
            SubjectType::Client => "client",
        }
    }
}

/// The agent acting on behalf of the subject, present when the request was
/// authenticated with an agent act-token.
#[derive(Clone, Debug)]
pub struct ActorContext {
    /// Public ULID of the acting agent (the token's `act` claim).
    pub agent_id: String,
    /// The delegation grant the token was minted against.
    pub delegation_id: String,
}

/// Authentication context attached to a request after successful token introspection.
///
/// `subject` is the gateway public identifier (never the raw Hydra client ID or
/// Kratos identity ID). Callers and audit logs should only see this value.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub tenant_id: String,
    pub subject: String,
    pub subject_type: SubjectType,
    /// The acting agent, when this request runs under a delegation grant.
    pub actor: Option<ActorContext>,
    pub scopes: Vec<String>,
    pub token_hash: String,
    /// Authentication Method Reference values asserted for this session.
    pub authentication_methods: Vec<String>,
}

/// Result of a token introspection call.
#[derive(Clone, Debug)]
pub struct IntrospectionResult {
    pub active: bool,
    pub sub: Option<String>,
    pub scope: Vec<String>,
    pub exp: Option<time::OffsetDateTime>,
    /// Authentication methods reported by the authorization server (e.g. Kratos
    /// session metadata passed through Hydra's `ext` claim).
    pub authentication_methods: Vec<String>,
}

impl IntrospectionResult {
    fn from_hydra(value: &Value) -> Self {
        let active = matches!(value["active"].as_bool(), Some(true));
        let sub = value["sub"].as_str().map(String::from);
        let scope = match value["scope"].as_str() {
            Some(s) => s.split(' ').map(String::from).collect(),
            None => Vec::new(),
        };
        let exp = value["exp"]
            .as_i64()
            .and_then(|ts| time::OffsetDateTime::from_unix_timestamp(ts).ok());
        let authentication_methods = parse_authentication_methods(value);
        Self {
            active,
            sub,
            scope,
            exp,
            authentication_methods,
        }
    }
}

/// Parse AMR values from a Hydra introspection response.
///
/// Hydra may return the methods under `ext.authentication_methods` or a
/// top-level `authentication_methods` key. Each entry may be an object with a
/// `method` field or a plain string.
fn parse_authentication_methods(value: &Value) -> Vec<String> {
    let amr = value
        .get("ext")
        .and_then(|ext| ext.get("authentication_methods"))
        .or_else(|| value.get("authentication_methods"));

    let Some(array) = amr.and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    array
        .iter()
        .filter_map(|entry| {
            if let Some(method) = entry.get("method").and_then(|m| m.as_str()) {
                Some(method.to_string())
            } else {
                entry.as_str().map(String::from)
            }
        })
        .collect()
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing authorization bearer token")]
    MissingToken,
    #[error("token introspection failed")]
    IntrospectionFailed(#[from] OryClientError),
    #[error("token is inactive or invalid")]
    InactiveToken,
    #[error("introspection response missing subject")]
    MissingSubject,
    #[error("unknown token subject")]
    UnknownSubject,
    #[error("database error: {0}")]
    Database(#[from] DbError),
}

#[async_trait]
pub trait TokenIntrospector: Send + Sync + 'static {
    async fn introspect(&self, token: &str) -> Result<IntrospectionResult, AuthError>;
}

/// Direct Hydra introspection with no caching.
#[derive(Clone)]
pub struct HydraTokenIntrospector {
    client: Arc<HydraClient>,
}

impl HydraTokenIntrospector {
    pub fn new(client: Arc<HydraClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl TokenIntrospector for HydraTokenIntrospector {
    #[instrument(skip(self, token), fields(token_hash = %hash_token(token)))]
    async fn introspect(&self, token: &str) -> Result<IntrospectionResult, AuthError> {
        debug!("introspecting token at Hydra");
        let value = self.client.introspect_token(token).await?;
        Ok(IntrospectionResult::from_hydra(&value))
    }
}

/// Postgres-cached introspection wrapper.
#[derive(Clone)]
pub struct CachedTokenIntrospector {
    inner: Arc<dyn TokenIntrospector>,
    cache: Arc<dyn TokenIntrospectionCache>,
    max_age: time::Duration,
}

impl CachedTokenIntrospector {
    pub fn new(
        inner: Arc<dyn TokenIntrospector>,
        cache: Arc<dyn TokenIntrospectionCache>,
        max_age: time::Duration,
    ) -> Self {
        Self {
            inner,
            cache,
            max_age,
        }
    }
}

#[async_trait]
impl TokenIntrospector for CachedTokenIntrospector {
    #[instrument(skip(self, token), fields(token_hash = %hash_token(token)))]
    async fn introspect(&self, token: &str) -> Result<IntrospectionResult, AuthError> {
        let token_hash = hash_token(token);

        if let Some(row) = self.cache.get(&token_hash, self.max_age).await? {
            debug!("token introspection cache hit");
            return Ok(IntrospectionResult {
                active: row.active,
                sub: row.sub,
                scope: match row.scope {
                    Some(s) => s.split(' ').map(String::from).collect(),
                    None => Vec::new(),
                },
                exp: row.exp,
                // The cache schema does not store AMR; callers that need
                // stepped-up assurance should bypass the cache or accept empty.
                authentication_methods: Vec::new(),
            });
        }

        debug!("token introspection cache miss");
        let result = self.inner.introspect(token).await?;

        // Do not cache inactive tokens; this limits the window after revocation.
        if !result.active {
            return Ok(result);
        }

        let scope_str = if result.scope.is_empty() {
            None
        } else {
            Some(result.scope.join(" "))
        };
        // Cache writes are best-effort: the introspection result is already
        // in hand, so a slow or failed cache store must not fail the request
        // (SSO-024). Log and continue without caching.
        if let Err(err) = self
            .cache
            .put(
                &token_hash,
                result.active,
                result.sub.as_deref(),
                scope_str.as_deref(),
                result.exp,
            )
            .await
        {
            warn!(%err, "token introspection cache write failed; continuing without caching");
        }
        Ok(result)
    }
}

/// Extract a bearer token from the `Authorization` header.
///
/// The `Bearer` prefix is matched case-insensitively and empty tokens are
/// rejected.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, token) = v.split_once(' ')?;
            if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
                return None;
            }
            Some(token.to_string())
        })
}

/// Hash a secret token for cache keys and audit logging.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Resolve an authenticated subject to a tenant using gateway id_mappings.
///
/// The subject may be a Hydra client ID (client-credentials tokens) or a
/// Kratos identity ID (user tokens), so both backends are queried. The first
/// match wins; if neither backend has a mapping the subject is unknown.
pub async fn resolve_tenant_from_subject(
    mappings: &dyn IdMappingStore,
    subject: &str,
) -> Result<String, AuthError> {
    for backend in ["hydra", "kratos"] {
        match mappings.get_tenant_id_by_ory_id(backend, subject).await {
            Ok(Some(tenant_id)) => return Ok(tenant_id),
            Ok(None) => continue,
            Err(e) => {
                warn!("failed to resolve tenant for subject: {}", e);
                return Err(AuthError::Database(e));
            }
        }
    }
    Err(AuthError::UnknownSubject)
}

/// Translate an Ory backend subject (Hydra client ID or Kratos identity ID)
/// into the gateway public identifier stored in id_mappings.
pub async fn resolve_public_subject(
    mappings: &dyn IdMappingStore,
    ory_subject: &str,
) -> Result<String, AuthError> {
    for backend in ["hydra", "kratos"] {
        match mappings.get_public_id_by_ory_id(backend, ory_subject).await {
            Ok(public_id) => return Ok(public_id),
            Err(DbError::MappingNotFound) => continue,
            Err(e) => {
                warn!("failed to resolve public subject: {}", e);
                return Err(AuthError::Database(e));
            }
        }
    }
    Err(AuthError::UnknownSubject)
}

/// Which Ory backend a subject resolved through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectBackend {
    Hydra,
    Kratos,
}

/// Resolve an authenticated subject to `(tenant_id, public_id, backend)` in a
/// single pass over the known backends. The first backend whose mapping
/// resolves both the tenant and the public id wins.
pub async fn resolve_subject(
    mappings: &dyn IdMappingStore,
    subject: &str,
) -> Result<(String, String, SubjectBackend), AuthError> {
    for (backend_name, backend) in [
        ("hydra", SubjectBackend::Hydra),
        ("kratos", SubjectBackend::Kratos),
    ] {
        match mappings
            .get_tenant_id_by_ory_id(backend_name, subject)
            .await
        {
            Ok(Some(tenant_id)) => {
                match mappings
                    .get_public_id_by_ory_id(backend_name, subject)
                    .await
                {
                    Ok(public_id) => return Ok((tenant_id, public_id, backend)),
                    Err(DbError::MappingNotFound) => continue,
                    Err(e) => {
                        warn!("failed to resolve public subject: {}", e);
                        return Err(AuthError::Database(e));
                    }
                }
            }
            Ok(None) => continue,
            Err(e) => {
                warn!("failed to resolve tenant for subject: {}", e);
                return Err(AuthError::Database(e));
            }
        }
    }
    Err(AuthError::UnknownSubject)
}

/// Build an `AuthContext` from an introspection result and tenant mapping.
pub fn build_auth_context(
    tenant_id: String,
    subject: String,
    subject_type: SubjectType,
    actor: Option<ActorContext>,
    scopes: Vec<String>,
    authentication_methods: Vec<String>,
    token: &str,
) -> AuthContext {
    AuthContext {
        tenant_id,
        subject,
        subject_type,
        actor,
        scopes,
        token_hash: hash_token(token),
        authentication_methods,
    }
}

/// Require a scope from the request's `AuthContext`.
pub fn require_scope(ctx: &RequestContext, scope: &str) -> Result<(), ServiceError> {
    let auth = ctx
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| ServiceError::Unauthenticated("missing authentication context".into()))?;
    if !auth.scopes.iter().any(|s| s == scope) {
        return Err(ServiceError::PermissionDenied(format!(
            "missing required scope: {scope}"
        )));
    }
    Ok(())
}

/// Require the authenticated subject to be of a specific type.
pub fn require_subject_type(
    ctx: &RequestContext,
    expected: SubjectType,
) -> Result<(), ServiceError> {
    let auth = ctx
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| ServiceError::Unauthenticated("missing authentication context".into()))?;
    if auth.subject_type != expected {
        return Err(ServiceError::PermissionDenied(format!(
            "requires a {} subject",
            expected.as_str()
        )));
    }
    Ok(())
}

/// Require an Authentication Method Reference from the request's `AuthContext`.
///
/// This helper is intended for RPC handlers that need stepped-up assurance
/// (e.g. admin operations requiring a second factor).
pub fn require_amr(ctx: &RequestContext, method: &str) -> Result<(), ServiceError> {
    let auth = ctx
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| ServiceError::Unauthenticated("missing authentication context".into()))?;
    if !auth.authentication_methods.iter().any(|m| m == method) {
        return Err(ServiceError::PermissionDenied(format!(
            "missing required authentication method: {method}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::TokenIntrospectionRow;
    use axum::http::HeaderValue;

    struct ActiveIntrospector;

    #[async_trait]
    impl TokenIntrospector for ActiveIntrospector {
        async fn introspect(&self, _token: &str) -> Result<IntrospectionResult, AuthError> {
            Ok(IntrospectionResult {
                active: true,
                sub: Some("subject-1".to_string()),
                scope: vec!["openid".to_string()],
                exp: None,
                authentication_methods: vec![],
            })
        }
    }

    /// Cache stub whose writes always fail, as with a wedged database.
    struct FailingWriteCache;

    #[async_trait]
    impl TokenIntrospectionCache for FailingWriteCache {
        async fn get(
            &self,
            _token_hash: &str,
            _max_age: time::Duration,
        ) -> Result<Option<TokenIntrospectionRow>, DbError> {
            Ok(None)
        }

        async fn put(
            &self,
            _token_hash: &str,
            _active: bool,
            _sub: Option<&str>,
            _scope: Option<&str>,
            _exp: Option<time::OffsetDateTime>,
        ) -> Result<(), DbError> {
            Err(DbError::Sqlx(sqlx::Error::RowNotFound))
        }

        async fn remove(&self, _token_hash: &str) -> Result<(), DbError> {
            Ok(())
        }
    }

    /// A failed cache write must not fail authentication (SSO-024): the
    /// introspection result is returned and the request proceeds uncached.
    #[tokio::test]
    async fn cached_introspector_fails_open_on_cache_write_error() {
        let introspector = CachedTokenIntrospector::new(
            Arc::new(ActiveIntrospector),
            Arc::new(FailingWriteCache),
            time::Duration::seconds(60),
        );
        let result = introspector.introspect("valid-token").await.unwrap();
        assert!(result.active);
        assert_eq!(result.sub, Some("subject-1".to_string()));
    }

    #[test]
    fn hash_token_is_deterministic_and_hex() {
        let h1 = hash_token("my-secret-token");
        let h2 = hash_token("my-secret-token");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_token_differs_for_different_tokens() {
        let h1 = hash_token("token-one");
        let h2 = hash_token("token-two");
        assert_ne!(h1, h2);
    }

    #[test]
    fn bearer_token_extracts_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token"),
        );
        assert_eq!(bearer_token(&headers), Some("secret-token".to_string()));
    }

    #[test]
    fn bearer_token_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("bearer secret-token"),
        );
        assert_eq!(bearer_token(&headers), Some("secret-token".to_string()));
    }

    #[test]
    fn bearer_token_rejects_empty_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert_eq!(bearer_token(&headers), None);
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
    fn introspection_result_parses_hydra_response() {
        let value = serde_json::json!({
            "active": true,
            "sub": "client-1",
            "scope": "openid tenant:read",
            "exp": 1893456000
        });
        let result = IntrospectionResult::from_hydra(&value);
        assert!(result.active);
        assert_eq!(result.sub, Some("client-1".to_string()));
        assert_eq!(result.scope, vec!["openid", "tenant:read"]);
        assert!(result.exp.is_some());
        assert!(result.authentication_methods.is_empty());
    }

    #[test]
    fn introspection_result_parses_ext_authentication_methods_objects() {
        let value = serde_json::json!({
            "active": true,
            "sub": "client-1",
            "scope": "openid",
            "ext": {
                "authentication_methods": [
                    {"method": "password"},
                    {"method": "totp"}
                ]
            }
        });
        let result = IntrospectionResult::from_hydra(&value);
        assert_eq!(result.authentication_methods, vec!["password", "totp"]);
    }

    #[test]
    fn introspection_result_parses_top_level_authentication_methods_strings() {
        let value = serde_json::json!({
            "active": true,
            "sub": "client-1",
            "scope": "openid",
            "authentication_methods": ["password", "webauthn"]
        });
        let result = IntrospectionResult::from_hydra(&value);
        assert_eq!(result.authentication_methods, vec!["password", "webauthn"]);
    }

    #[test]
    fn build_auth_context_includes_authentication_methods() {
        let ctx = build_auth_context(
            "tenant-1".into(),
            "sub-1".into(),
            SubjectType::User,
            None,
            vec!["tenant:read".into()],
            vec!["password".into(), "totp".into()],
            "secret-token",
        );
        assert_eq!(ctx.tenant_id, "tenant-1");
        assert_eq!(ctx.authentication_methods, vec!["password", "totp"]);
    }

    #[test]
    fn require_scope_enforces_scope() {
        let mut ctx = RequestContext::default();
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "sub-1".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec!["tenant:read".into()],
            token_hash: "hash".into(),
            authentication_methods: vec![],
        });
        assert!(require_scope(&ctx, "tenant:read").is_ok());
        let err = require_scope(&ctx, "tenant:write").unwrap_err();
        assert!(matches!(err, ServiceError::PermissionDenied(_)));
    }

    #[test]
    fn require_scope_requires_auth_context() {
        let ctx = RequestContext::default();
        let err = require_scope(&ctx, "tenant:read").unwrap_err();
        assert!(matches!(err, ServiceError::Unauthenticated(_)));
    }

    #[test]
    fn require_amr_accepts_matching_method() {
        let mut ctx = RequestContext::default();
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "sub-1".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec![],
            token_hash: "hash".into(),
            authentication_methods: vec!["password".into(), "totp".into()],
        });
        assert!(require_amr(&ctx, "password").is_ok());
        assert!(require_amr(&ctx, "totp").is_ok());
    }

    #[test]
    fn require_amr_rejects_missing_method() {
        let mut ctx = RequestContext::default();
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "sub-1".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec![],
            token_hash: "hash".into(),
            authentication_methods: vec!["password".into()],
        });
        let err = require_amr(&ctx, "totp").unwrap_err();
        assert!(matches!(err, ServiceError::PermissionDenied(_)));
    }

    #[test]
    fn require_amr_requires_auth_context() {
        let ctx = RequestContext::default();
        let err = require_amr(&ctx, "password").unwrap_err();
        assert!(matches!(err, ServiceError::Unauthenticated(_)));
    }

    /// Stub mapping store that returns a tenant only for a specific backend.
    struct BackendMappingStore {
        hydra_tenant: Option<String>,
        kratos_tenant: Option<String>,
        queried_backends: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl IdMappingStore for BackendMappingStore {
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
            backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, crate::db::DbError> {
            self.queried_backends
                .lock()
                .unwrap()
                .push(backend.to_string());
            match backend {
                "hydra" => Ok(self.hydra_tenant.clone()),
                "kratos" => Ok(self.kratos_tenant.clone()),
                _ => Ok(None),
            }
        }
    }

    #[tokio::test]
    async fn resolve_tenant_queries_hydra_then_kratos() {
        let store = BackendMappingStore {
            hydra_tenant: None,
            kratos_tenant: Some("tenant-k".to_string()),
            queried_backends: std::sync::Mutex::new(Vec::new()),
        };
        let tenant = resolve_tenant_from_subject(&store, "subject-1")
            .await
            .unwrap();
        assert_eq!(tenant, "tenant-k");
        let backends = store.queried_backends.lock().unwrap();
        assert_eq!(backends.len(), 2);
        assert_eq!(backends[0], "hydra");
        assert_eq!(backends[1], "kratos");
    }

    #[tokio::test]
    async fn resolve_tenant_prefers_hydra_mapping() {
        let store = BackendMappingStore {
            hydra_tenant: Some("tenant-h".to_string()),
            kratos_tenant: Some("tenant-k".to_string()),
            queried_backends: std::sync::Mutex::new(Vec::new()),
        };
        let tenant = resolve_tenant_from_subject(&store, "subject-1")
            .await
            .unwrap();
        assert_eq!(tenant, "tenant-h");
        let backends = store.queried_backends.lock().unwrap();
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0], "hydra");
    }

    #[tokio::test]
    async fn resolve_tenant_returns_unknown_for_missing_mapping() {
        let store = BackendMappingStore {
            hydra_tenant: None,
            kratos_tenant: None,
            queried_backends: std::sync::Mutex::new(Vec::new()),
        };
        let err = resolve_tenant_from_subject(&store, "subject-1")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::UnknownSubject));
        let backends = store.queried_backends.lock().unwrap();
        assert_eq!(backends.len(), 2);
    }
}
