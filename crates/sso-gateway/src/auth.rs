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

/// Authentication context attached to a request after successful token introspection.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub tenant_id: String,
    pub subject: String,
    pub scopes: Vec<String>,
    pub token_hash: String,
}

/// Result of a token introspection call.
#[derive(Clone, Debug)]
pub struct IntrospectionResult {
    pub active: bool,
    pub sub: Option<String>,
    pub scope: Vec<String>,
    pub exp: Option<time::OffsetDateTime>,
}

impl IntrospectionResult {
    fn from_hydra(value: &Value) -> Self {
        let active = value["active"].as_bool().unwrap_or(false);
        let sub = value["sub"].as_str().map(String::from);
        let scope = value["scope"]
            .as_str()
            .map(|s| s.split(' ').map(String::from).collect())
            .unwrap_or_default();
        let exp = value["exp"]
            .as_i64()
            .and_then(|ts| time::OffsetDateTime::from_unix_timestamp(ts).ok());
        Self {
            active,
            sub,
            scope,
            exp,
        }
    }
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
                scope: row
                    .scope
                    .map(|s| s.split(' ').map(String::from).collect())
                    .unwrap_or_default(),
                exp: row.exp,
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
        self.cache
            .put(
                &token_hash,
                result.active,
                result.sub.as_deref(),
                scope_str.as_deref(),
                result.exp,
            )
            .await?;
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
pub async fn resolve_tenant_from_subject(
    mappings: &dyn IdMappingStore,
    subject: &str,
) -> Result<String, AuthError> {
    let tenant_id = mappings
        .get_tenant_id_by_ory_id("hydra", subject)
        .await
        .map_err(|e| {
            warn!("failed to resolve tenant for subject {}: {}", subject, e);
            AuthError::Database(e)
        })?
        .ok_or(AuthError::UnknownSubject)?;
    Ok(tenant_id)
}

/// Build an `AuthContext` from an introspection result and tenant mapping.
pub fn build_auth_context(
    tenant_id: String,
    subject: String,
    scopes: Vec<String>,
    token: &str,
) -> AuthContext {
    AuthContext {
        tenant_id,
        subject,
        scopes,
        token_hash: hash_token(token),
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

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
    }

    #[test]
    fn require_scope_enforces_scope() {
        let mut ctx = RequestContext::default();
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "sub-1".into(),
            scopes: vec!["tenant:read".into()],
            token_hash: "hash".into(),
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
}
