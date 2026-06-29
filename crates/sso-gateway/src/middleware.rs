use axum::{
    Extension,
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use connectrpc::RequestContext;

use crate::db::{AuditLogRepo, DbError, TenantApiKeyRepo};
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

pub async fn auth_middleware(
    Extension(api_keys): Extension<TenantApiKeyRepo>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    // Public OAuth2/OIDC discovery and browser flows perform their own tenant
    // validation (via client_id or explicit x-tenant-id in handlers).
    if path.starts_with("/.well-known/")
        || path.starts_with("/oauth2/")
        || path.starts_with("/scim/")
        || path.starts_with("/saml/")
    {
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

async fn authenticate_api_key(
    repo: &TenantApiKeyRepo,
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
    let metadata = serde_json::json!({
        "status": response.status().as_u16(),
    });

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
            resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

}
