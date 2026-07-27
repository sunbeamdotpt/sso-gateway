use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;
use ulid::Ulid;

use crate::auth::{AuthContext, SCOPE_IDENTITY_ADMIN, SCOPE_TENANT_ADMIN};
use crate::db::{
    DbError, IdMappingRepo, IdMappingStore, TOKEN_TYPE_CONSENT_CHALLENGE,
    TOKEN_TYPE_LOGOUT_CHALLENGE, TransientTokenRepo, TransientTokenStore,
};
use crate::middleware::TenantId;
use crate::proto::iam::v1::{
    AcceptConsentRequest, AcceptLogoutRequest, ConsentRequest, ConsentResponse,
    GetChallengeRequest, LogoutRequest, LogoutResponse, OAuth2ConsentService, RejectConsentRequest,
    RejectLogoutRequest,
};

use super::oauth2_consent_mapper::{
    accept_consent_request_to_json, accept_logout_request_to_json, inject_identity_id_claim,
    ory_consent_request_to_proto, ory_consent_response_to_proto, ory_logout_request_to_proto,
    ory_logout_response_to_proto, reject_consent_request_to_json, reject_logout_request_to_json,
};

const BACKEND_HYDRA: &str = "hydra";
const BACKEND_KRATOS: &str = "kratos";

fn challenge_expiry() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::hours(1)
}

fn map_db_error(err: DbError) -> ServiceError {
    match err {
        DbError::MappingNotFound => ServiceError::NotFound("mapping not found".into()),
        _ => ServiceError::Database(err.to_string()),
    }
}

/// Hydra operations used by the OAuth2 consent service.
#[async_trait]
pub trait ConsentHydra: Send + Sync {
    async fn get_consent_request(&self, challenge: &str) -> Result<Value, OryClientError>;
    async fn accept_consent_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError>;
    async fn reject_consent_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError>;
    async fn get_logout_request(&self, challenge: &str) -> Result<Value, OryClientError>;
    async fn accept_logout_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError>;
    async fn reject_logout_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError>;
}

#[async_trait]
impl ConsentHydra for HydraClient {
    async fn get_consent_request(&self, challenge: &str) -> Result<Value, OryClientError> {
        self.get_consent_request(challenge).await
    }

    async fn accept_consent_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.accept_consent_request(challenge, body).await
    }

    async fn reject_consent_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.reject_consent_request(challenge, body).await
    }

    async fn get_logout_request(&self, challenge: &str) -> Result<Value, OryClientError> {
        self.get_logout_request(challenge).await
    }

    async fn accept_logout_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.accept_logout_request(challenge, body).await
    }

    async fn reject_logout_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.reject_logout_request(challenge, body).await
    }
}

#[derive(Clone)]
pub struct OAuth2ConsentServiceImpl {
    hydra: Arc<dyn ConsentHydra>,
    transient: Arc<dyn TransientTokenStore>,
    mappings: Arc<dyn IdMappingStore>,
}

impl OAuth2ConsentServiceImpl {
    pub fn new(
        hydra: Arc<HydraClient>,
        transient: TransientTokenRepo,
        mappings: IdMappingRepo,
    ) -> Self {
        Self {
            hydra: hydra as Arc<dyn ConsentHydra>,
            transient: Arc::new(transient) as Arc<dyn TransientTokenStore>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
        }
    }
}

fn require_tenant(ctx: &RequestContext) -> Result<String, ServiceError> {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .ok_or_else(|| ServiceError::Unauthenticated("missing tenant".into()))
}

/// Tenant from the request context, defaulting to empty when the caller is
/// unauthenticated. Used only as the fallback tenant for raw-challenge
/// passthrough; mapped challenges resolve their tenant from the mapping row.
fn tenant_from_ctx(ctx: &RequestContext) -> String {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .unwrap_or_default()
}

fn require_consent_admin(ctx: &RequestContext) -> Result<(), ServiceError> {
    if require_scope(ctx, SCOPE_TENANT_ADMIN).is_ok()
        || require_scope(ctx, SCOPE_IDENTITY_ADMIN).is_ok()
    {
        return Ok(());
    }
    Err(ServiceError::PermissionDenied(
        "missing required scope: tenant:admin or identity:admin".into(),
    ))
}

fn require_scope(ctx: &RequestContext, scope: &str) -> Result<(), ServiceError> {
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

impl OAuth2ConsentServiceImpl {
    async fn ory_challenge(
        &self,
        tenant_id: &str,
        public_challenge: &str,
        token_type: &str,
    ) -> Result<String, ServiceError> {
        match self
            .transient
            .get_ory_token(tenant_id, BACKEND_HYDRA, token_type, public_challenge)
            .await
        {
            Ok(ory_challenge) => Ok(ory_challenge),
            // Hydra's post-login redirect delivers the raw Hydra challenge to
            // the consent app in the consent_challenge query parameter, so
            // there is no mapping to resolve. Hydra still cryptographically
            // validates the challenge, so passthrough is safe (mirrors
            // resolve_login_challenge in identity_self_service).
            Err(DbError::MappingNotFound) => Ok(public_challenge.to_string()),
            Err(err) => Err(map_db_error(err)),
        }
    }

    async fn public_challenge(
        &self,
        tenant_id: &str,
        ory_challenge: &str,
        token_type: &str,
    ) -> Result<String, ServiceError> {
        match self
            .transient
            .get_public_token(tenant_id, BACKEND_HYDRA, token_type, ory_challenge)
            .await
        {
            Ok(public) => Ok(public),
            Err(DbError::MappingNotFound) => self
                .transient
                .create(
                    tenant_id,
                    BACKEND_HYDRA,
                    token_type,
                    ory_challenge,
                    challenge_expiry(),
                )
                .await
                .map_err(map_db_error),
            Err(e) => Err(map_db_error(e)),
        }
    }

    async fn resolve_logout_challenge(
        &self,
        fallback_tenant_id: &str,
        public_challenge: &str,
    ) -> Result<(String, String), ServiceError> {
        match self
            .transient
            .get_ory_token_global(BACKEND_HYDRA, TOKEN_TYPE_LOGOUT_CHALLENGE, public_challenge)
            .await
        {
            Ok(resolved) => Ok(resolved),
            // Hydra's redirect to the logout app carries the raw Hydra logout
            // challenge in the logout_challenge query parameter, so there is
            // no mapping to resolve. Hydra still cryptographically validates
            // the challenge, so passthrough is safe (mirrors
            // resolve_login_challenge); the tenant falls back to the caller's
            // tenant from the request context.
            Err(DbError::MappingNotFound) => {
                Ok((fallback_tenant_id.to_string(), public_challenge.to_string()))
            }
            Err(err) => Err(map_db_error(err)),
        }
    }

    async fn public_client_id(
        &self,
        tenant_id: &str,
        ory_client_id: &str,
    ) -> Result<String, ServiceError> {
        if ory_client_id.is_empty() {
            return Ok(String::new());
        }
        self.mappings
            .get_public_id(tenant_id, BACKEND_HYDRA, ory_client_id)
            .await
            .map_err(map_db_error)
    }

    async fn public_subject(
        &self,
        tenant_id: &str,
        ory_subject: &str,
    ) -> Result<String, ServiceError> {
        if ory_subject.is_empty() {
            return Ok(String::new());
        }
        match self
            .mappings
            .get_public_id(tenant_id, BACKEND_KRATOS, ory_subject)
            .await
        {
            Ok(public_id) => Ok(public_id),
            Err(DbError::MappingNotFound) => {
                // Pre-existing Kratos identity that was never mapped in the
                // gateway (e.g., created before self-service provisioning was
                // added, or migrated from another environment). Mint a public
                // id and create the mapping so consent/login flows can proceed.
                // The tenant membership is backfilled on the first read via
                // `IdentityServiceImpl::resolve_identity`.
                let public_id = Ulid::new().to_string();
                self.mappings
                    .create(tenant_id, BACKEND_KRATOS, &public_id, ory_subject)
                    .await
                    .map_err(map_db_error)?;
                Ok(public_id)
            }
            Err(err) => Err(map_db_error(err)),
        }
    }

    async fn map_consent_request(
        &self,
        tenant_id: &str,
        mut consent: ConsentRequest,
    ) -> Result<ConsentRequest, ServiceError> {
        consent.challenge = self
            .public_challenge(tenant_id, &consent.challenge, TOKEN_TYPE_CONSENT_CHALLENGE)
            .await?;
        consent.client_id = self.public_client_id(tenant_id, &consent.client_id).await?;
        consent.subject = self.public_subject(tenant_id, &consent.subject).await?;
        if let Some(client) = consent.client.as_option_mut() {
            client.client_id = self.public_client_id(tenant_id, &client.client_id).await?;
        }
        Ok(consent)
    }

    async fn map_logout_request(
        &self,
        tenant_id: &str,
        mut logout: LogoutRequest,
    ) -> Result<LogoutRequest, ServiceError> {
        logout.challenge = self
            .public_challenge(tenant_id, &logout.challenge, TOKEN_TYPE_LOGOUT_CHALLENGE)
            .await?;
        logout.client_id = self.public_client_id(tenant_id, &logout.client_id).await?;
        logout.subject = self.public_subject(tenant_id, &logout.subject).await?;
        if let Some(client) = logout.client.as_option_mut() {
            client.client_id = self.public_client_id(tenant_id, &client.client_id).await?;
        }
        Ok(logout)
    }
}

#[allow(refining_impl_trait)]
impl OAuth2ConsentService for OAuth2ConsentServiceImpl {
    #[instrument(skip(self, request))]
    async fn get_consent_request(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetChallengeRequest>,
    ) -> ServiceResult<ConsentRequest> {
        require_consent_admin(&ctx)?;
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let ory_challenge = self
            .ory_challenge(&tenant_id, &req.challenge, TOKEN_TYPE_CONSENT_CHALLENGE)
            .await?;

        let value = self
            .hydra
            .get_consent_request(&ory_challenge)
            .await
            .map_err(map_ory_error)?;
        let consent = ory_consent_request_to_proto(&value);
        Ok(Response::new(
            self.map_consent_request(&tenant_id, consent).await?,
        ))
    }

    #[instrument(skip(self, request))]
    async fn accept_consent(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AcceptConsentRequest>,
    ) -> ServiceResult<ConsentResponse> {
        require_consent_admin(&ctx)?;
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let ory_challenge = self
            .ory_challenge(&tenant_id, &req.challenge, TOKEN_TYPE_CONSENT_CHALLENGE)
            .await?;

        // Fetch the consent request first to enforce that the challenge exists,
        // has not been handled yet, and to obtain the requested scopes/subject.
        let consent_value = self
            .hydra
            .get_consent_request(&ory_challenge)
            .await
            .map_err(map_ory_error)?;
        let consent = ory_consent_request_to_proto(&consent_value);

        let requested: HashSet<_> = consent.requested_scope.iter().cloned().collect();
        if !req.grant_scope.iter().all(|s| requested.contains(s)) {
            return Err(ServiceError::InvalidArgument(
                "grant_scope exceeds requested_scope".into(),
            )
            .into());
        }

        let auth = ctx.extensions().get::<AuthContext>().ok_or_else(|| {
            ServiceError::Unauthenticated("missing authentication context".into())
        })?;
        let is_tenant_admin = auth.scopes.iter().any(|s| s == SCOPE_TENANT_ADMIN);
        // Resolve the public identity id for the id_token `identity_id` claim
        // without backfilling. This must run before `public_subject`, which
        // mints a mapping for unmapped subjects; an unmapped subject never
        // fails consent — the claim is skipped with a warning and userinfo
        // stays the documented fallback.
        let identity_claim = if consent.subject.is_empty() {
            None
        } else {
            match self
                .mappings
                .get_public_id(&tenant_id, BACKEND_KRATOS, &consent.subject)
                .await
            {
                Ok(public_id) => Some(public_id),
                Err(DbError::MappingNotFound) => {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        subject = %consent.subject,
                        "consent subject has no identity mapping; id_token issued without identity_id claim"
                    );
                    None
                }
                Err(err) => return Err(map_db_error(err).into()),
            }
        };
        let public_subject = self.public_subject(&tenant_id, &consent.subject).await?;
        if auth.subject != public_subject && !is_tenant_admin {
            return Err(ServiceError::PermissionDenied(
                "cannot accept consent for another subject".into(),
            )
            .into());
        }

        let mut body = accept_consent_request_to_json(&req);
        // Stamp the public iam identity id into the id_token claims so callers
        // can join the signed-in user to iam records; `sub` stays the backend
        // identity UUID. A caller-supplied `identity_id` wins.
        if let Some(identity_id) = &identity_claim {
            inject_identity_id_claim(&mut body, identity_id);
        }
        let value = self
            .hydra
            .accept_consent_request(&ory_challenge, body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_consent_response_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn reject_consent(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RejectConsentRequest>,
    ) -> ServiceResult<ConsentResponse> {
        require_consent_admin(&ctx)?;
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let ory_challenge = self
            .ory_challenge(&tenant_id, &req.challenge, TOKEN_TYPE_CONSENT_CHALLENGE)
            .await?;
        let body = reject_consent_request_to_json(&req);
        let value = self
            .hydra
            .reject_consent_request(&ory_challenge, body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_consent_response_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn get_logout_request(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetChallengeRequest>,
    ) -> ServiceResult<LogoutRequest> {
        let req = request.to_owned_message();
        let (tenant_id, ory_challenge) = self
            .resolve_logout_challenge(&tenant_from_ctx(&ctx), &req.challenge)
            .await?;
        let value = self
            .hydra
            .get_logout_request(&ory_challenge)
            .await
            .map_err(map_ory_error)?;
        let logout = ory_logout_request_to_proto(&value);
        Ok(Response::new(
            self.map_logout_request(&tenant_id, logout).await?,
        ))
    }

    #[instrument(skip(self, request))]
    async fn accept_logout(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AcceptLogoutRequest>,
    ) -> ServiceResult<LogoutResponse> {
        let req = request.to_owned_message();
        let (_tenant_id, ory_challenge) = self
            .resolve_logout_challenge(&tenant_from_ctx(&ctx), &req.challenge)
            .await?;
        let body = accept_logout_request_to_json(&req);
        let value = self
            .hydra
            .accept_logout_request(&ory_challenge, body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_logout_response_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn reject_logout(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RejectLogoutRequest>,
    ) -> ServiceResult<LogoutResponse> {
        let req = request.to_owned_message();
        let (_tenant_id, ory_challenge) = self
            .resolve_logout_challenge(&tenant_from_ctx(&ctx), &req.challenge)
            .await?;
        let body = reject_logout_request_to_json(&req);
        let value = self
            .hydra
            .reject_logout_request(&ory_challenge, body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_logout_response_to_proto(&value)))
    }
}

fn map_ory_error(err: OryClientError) -> ServiceError {
    use sso_ory_client::error::OryClientError;
    match err {
        OryClientError::Ory { status, message } => match status {
            400 => ServiceError::InvalidArgument(message),
            401 => ServiceError::Unauthenticated(message),
            403 => ServiceError::PermissionDenied(message),
            404 => ServiceError::NotFound(message),
            409 => ServiceError::AlreadyExists(message),
            503 => ServiceError::Unavailable(message),
            _ => ServiceError::Internal(message),
        },
        OryClientError::Http(_) | OryClientError::Url(_) => {
            ServiceError::Unavailable("upstream oauth2 service unreachable".into())
        }
        OryClientError::Serialization(_) | OryClientError::InvalidResponse(_) => {
            ServiceError::Internal("invalid upstream response".into())
        }
        OryClientError::MissingTenant => ServiceError::Unauthenticated("missing tenant".into()),
        OryClientError::Redirect { .. } => ServiceError::Internal("unexpected redirect".into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::SubjectType;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use buffa::Message;
    use buffa::bytes::Bytes;
    use buffa::view::{HasMessageView, MessageView};
    use connectrpc::{ErrorCode, RequestContext, ServiceRequest};
    use http::HeaderMap;
    use serde_json::{Value, json};
    use sso_ory_client::{error::OryClientError, hydra::HydraClient};
    use sunbeam_g2v::error::ServiceError;
    use ulid::Ulid;

    use crate::auth::{AuthContext, SCOPE_IDENTITY_ADMIN, SCOPE_TENANT_ADMIN};
    use crate::db::{
        IdMappingRow, IdMappingStore, TOKEN_TYPE_CONSENT_CHALLENGE, TOKEN_TYPE_LOGOUT_CHALLENGE,
        TransientTokenRepo, TransientTokenRow, TransientTokenStore,
    };
    use crate::middleware::TenantId;
    use crate::proto::iam::v1::{
        AcceptConsentRequest, AcceptLogoutRequest, GetChallengeRequest, OAuth2ConsentService,
        RejectConsentRequest, RejectLogoutRequest,
    };

    use super::{ConsentHydra, OAuth2ConsentServiceImpl, map_ory_error};

    #[derive(Debug, Clone)]
    enum Call {
        GetConsent(String),
        AcceptConsent(String),
        RejectConsent(String),
        GetLogout(String),
        AcceptLogout(String),
        RejectLogout(String),
    }

    #[derive(Clone, Default)]
    struct MockConsentHydra {
        results: Arc<Mutex<VecDeque<Result<Value, OryClientError>>>>,
        calls: Arc<Mutex<Vec<Call>>>,
        accept_bodies: Arc<Mutex<Vec<Value>>>,
    }

    impl MockConsentHydra {
        fn queue(&self, result: Result<Value, OryClientError>) {
            self.results.lock().unwrap().push_back(result);
        }

        fn take_result(&self) -> Result<Value, OryClientError> {
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock result not queued")
        }

        fn take_calls(&self) -> Vec<Call> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }

        fn take_accept_bodies(&self) -> Vec<Value> {
            std::mem::take(&mut *self.accept_bodies.lock().unwrap())
        }
    }

    #[async_trait::async_trait]
    impl ConsentHydra for MockConsentHydra {
        async fn get_consent_request(&self, challenge: &str) -> Result<Value, OryClientError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::GetConsent(challenge.to_string()));
            self.take_result()
        }

        async fn accept_consent_request(
            &self,
            challenge: &str,
            body: Value,
        ) -> Result<Value, OryClientError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::AcceptConsent(challenge.to_string()));
            self.accept_bodies.lock().unwrap().push(body);
            self.take_result()
        }

        async fn reject_consent_request(
            &self,
            challenge: &str,
            _body: Value,
        ) -> Result<Value, OryClientError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::RejectConsent(challenge.to_string()));
            self.take_result()
        }

        async fn get_logout_request(&self, challenge: &str) -> Result<Value, OryClientError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::GetLogout(challenge.to_string()));
            self.take_result()
        }

        async fn accept_logout_request(
            &self,
            challenge: &str,
            _body: Value,
        ) -> Result<Value, OryClientError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::AcceptLogout(challenge.to_string()));
            self.take_result()
        }

        async fn reject_logout_request(
            &self,
            challenge: &str,
            _body: Value,
        ) -> Result<Value, OryClientError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::RejectLogout(challenge.to_string()));
            self.take_result()
        }
    }

    #[derive(Default)]
    struct StubTransientTokenStore {
        rows: Mutex<Vec<TransientTokenRow>>,
    }

    impl StubTransientTokenStore {
        fn seed(
            &self,
            tenant_id: &str,
            backend: &str,
            token_type: &str,
            public_token: &str,
            ory_token: &str,
        ) {
            self.rows.lock().unwrap().push(TransientTokenRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                token_type: token_type.to_string(),
                public_token: public_token.to_string(),
                ory_token: ory_token.to_string(),
                expires_at: super::challenge_expiry(),
                created_at: time::OffsetDateTime::now_utc(),
            });
        }
    }

    #[async_trait::async_trait]
    impl TransientTokenStore for StubTransientTokenStore {
        async fn create(
            &self,
            tenant_id: &str,
            backend: &str,
            token_type: &str,
            ory_token: &str,
            expires_at: time::OffsetDateTime,
        ) -> Result<String, crate::db::DbError> {
            let rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter().find(|r| {
                r.backend == backend && r.token_type == token_type && r.ory_token == ory_token
            }) {
                return Ok(row.public_token.clone());
            }
            drop(rows);
            let public_token = Ulid::new().to_string();
            self.rows.lock().unwrap().push(TransientTokenRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                token_type: token_type.to_string(),
                public_token: public_token.clone(),
                ory_token: ory_token.to_string(),
                expires_at,
                created_at: time::OffsetDateTime::now_utc(),
            });
            Ok(public_token)
        }

        async fn get_ory_token(
            &self,
            _tenant_id: &str,
            backend: &str,
            token_type: &str,
            public_token: &str,
        ) -> Result<String, crate::db::DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| {
                    r.backend == backend
                        && r.token_type == token_type
                        && r.public_token == public_token
                })
                .map(|r| r.ory_token.clone())
                .ok_or(crate::db::DbError::MappingNotFound)
        }

        async fn get_public_token(
            &self,
            _tenant_id: &str,
            backend: &str,
            token_type: &str,
            ory_token: &str,
        ) -> Result<String, crate::db::DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| {
                    r.backend == backend && r.token_type == token_type && r.ory_token == ory_token
                })
                .map(|r| r.public_token.clone())
                .ok_or(crate::db::DbError::MappingNotFound)
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            public_token: &str,
        ) -> Result<(), crate::db::DbError> {
            let mut rows = self.rows.lock().unwrap();
            let pos = rows.iter().position(|r| r.public_token == public_token);
            pos.map(|i| rows.remove(i))
                .map(|_| ())
                .ok_or(crate::db::DbError::MappingNotFound)
        }

        async fn get_ory_token_global(
            &self,
            backend: &str,
            token_type: &str,
            public_token: &str,
        ) -> Result<(String, String), crate::db::DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| {
                    r.backend == backend
                        && r.token_type == token_type
                        && r.public_token == public_token
                })
                .map(|r| (r.tenant_id.clone(), r.ory_token.clone()))
                .ok_or(crate::db::DbError::MappingNotFound)
        }
    }

    #[derive(Default)]
    struct StubMappingStore {
        rows: Mutex<Vec<IdMappingRow>>,
    }

    impl StubMappingStore {
        fn with_mapping(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
            ory_global_id: &str,
        ) -> Self {
            let row = IdMappingRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                public_id: public_id.to_string(),
                ory_global_id: ory_global_id.to_string(),
                created_at: time::OffsetDateTime::now_utc(),
            };
            self.rows.lock().unwrap().push(row);
            Self {
                rows: Mutex::new(std::mem::take(&mut *self.rows.lock().unwrap())),
            }
        }
    }

    #[async_trait::async_trait]
    impl IdMappingStore for StubMappingStore {
        async fn create(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
            ory_global_id: &str,
        ) -> Result<IdMappingRow, crate::db::DbError> {
            let row = IdMappingRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                public_id: public_id.to_string(),
                ory_global_id: ory_global_id.to_string(),
                created_at: time::OffsetDateTime::now_utc(),
            };
            self.rows.lock().unwrap().push(row.clone());
            Ok(row)
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
            tenant_id: &str,
            backend: &str,
            ory_global_id: &str,
        ) -> Result<String, crate::db::DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| {
                    r.tenant_id == tenant_id
                        && r.backend == backend
                        && r.ory_global_id == ory_global_id
                })
                .map(|r| r.public_id.clone())
                .ok_or(crate::db::DbError::MappingNotFound)
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
            Ok(None)
        }
    }

    fn default_transient_store() -> StubTransientTokenStore {
        let store = StubTransientTokenStore::default();
        store.seed(
            "tenant-1",
            super::BACKEND_HYDRA,
            TOKEN_TYPE_CONSENT_CHALLENGE,
            "pub-consent-1",
            "consent-challenge-1",
        );
        store.seed(
            "tenant-1",
            super::BACKEND_HYDRA,
            TOKEN_TYPE_CONSENT_CHALLENGE,
            "pub-consent-2",
            "consent-challenge-2",
        );
        store.seed(
            "tenant-1",
            super::BACKEND_HYDRA,
            TOKEN_TYPE_CONSENT_CHALLENGE,
            "pub-consent-3",
            "consent-challenge-3",
        );
        store.seed(
            "tenant-1",
            super::BACKEND_HYDRA,
            TOKEN_TYPE_LOGOUT_CHALLENGE,
            "pub-logout-1",
            "logout-challenge-1",
        );
        store.seed(
            "tenant-1",
            super::BACKEND_HYDRA,
            TOKEN_TYPE_LOGOUT_CHALLENGE,
            "pub-logout-2",
            "logout-challenge-2",
        );
        store.seed(
            "tenant-1",
            super::BACKEND_HYDRA,
            TOKEN_TYPE_LOGOUT_CHALLENGE,
            "pub-logout-3",
            "logout-challenge-3",
        );
        store
    }

    fn default_mapping_store() -> StubMappingStore {
        StubMappingStore::default()
            .with_mapping("tenant-1", super::BACKEND_HYDRA, "pub-client-1", "client-1")
            .with_mapping(
                "tenant-1",
                super::BACKEND_KRATOS,
                "subject-1",
                "ory-subject-1",
            )
            .with_mapping(
                "tenant-1",
                super::BACKEND_KRATOS,
                "other-subject",
                "ory-other-subject",
            )
    }

    fn service(hydra: Arc<dyn ConsentHydra>) -> OAuth2ConsentServiceImpl {
        OAuth2ConsentServiceImpl {
            hydra,
            transient: Arc::new(default_transient_store()),
            mappings: Arc::new(default_mapping_store()),
        }
    }

    fn request_context() -> RequestContext {
        RequestContext::new(HeaderMap::new())
    }

    fn auth_context(scopes: &[&str]) -> RequestContext {
        let mut ctx = RequestContext::new(HeaderMap::new());
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "subject-1".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token_hash: "hash".into(),
            authentication_methods: Vec::new(),
        });
        ctx.extensions_mut().insert(TenantId("tenant-1".into()));
        ctx
    }

    fn decode_request<'a, Req: HasMessageView>(
        bytes: &'a Bytes,
    ) -> Result<Req::View<'a>, sunbeam_g2v::error::ServiceError> {
        <Req::View<'a> as MessageView>::decode_view(bytes).map_err(|e| {
            sunbeam_g2v::error::ServiceError::Internal(format!(
                "failed to decode self-encoded request: {e}"
            ))
        })
    }

    macro_rules! svc_req {
        ($id:ident, $req:expr, $ty:ty) => {
            let bytes = Bytes::from($req.encode_to_vec());
            let view = decode_request::<$ty>(&bytes).unwrap();
            let $id = ServiceRequest::<$ty>::from_parts(&view, &bytes);
        };
    }

    #[test]
    fn map_ory_error_status_codes() {
        let cases = vec![
            (400, "InvalidArgument"),
            (401, "Unauthenticated"),
            (403, "PermissionDenied"),
            (404, "NotFound"),
            (409, "AlreadyExists"),
            (503, "Unavailable"),
            (500, "Internal"),
        ];
        for (status, expected) in cases {
            let err = map_ory_error(OryClientError::Ory {
                status,
                message: "msg".into(),
            });
            let name = format!("{err:?}");
            assert!(
                name.contains(expected),
                "status {status} should map to {expected}, got {name}"
            );
        }
    }

    #[test]
    fn map_ory_error_transport_and_serialization() {
        let http = map_ory_error(OryClientError::Http(
            reqwest::Client::new().get("not-a-url").build().unwrap_err(),
        ));
        let url = map_ory_error(OryClientError::Url(
            reqwest::Url::parse("not a url").unwrap_err(),
        ));
        let ser = map_ory_error(OryClientError::Serialization(
            serde_json::from_str::<serde_json::Value>("not json").unwrap_err(),
        ));
        let invalid = map_ory_error(OryClientError::InvalidResponse("bad payload".into()));
        let missing = map_ory_error(OryClientError::MissingTenant);

        assert!(matches!(http, ServiceError::Unavailable(_)));
        assert!(matches!(url, ServiceError::Unavailable(_)));
        assert!(matches!(ser, ServiceError::Internal(_)));
        assert!(matches!(invalid, ServiceError::Internal(_)));
        assert!(matches!(missing, ServiceError::Unauthenticated(_)));
    }

    #[tokio::test]
    async fn oauth2_consent_service_impl_new_stores_hydra() {
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost:5432/unused").unwrap();
        let hydra = Arc::new(HydraClient::new("http://localhost:1", "http://localhost:1").unwrap());
        let service = OAuth2ConsentServiceImpl::new(
            hydra,
            TransientTokenRepo::new(pool.clone()),
            crate::db::IdMappingRepo::new(pool),
        );
        let _cloned = service.clone();
    }

    #[tokio::test]
    async fn get_consent_request_happy_path() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "consent-challenge-1",
            "client": { "client_id": "client-1", "client_name": "App" },
            "subject": "ory-subject-1",
            "skip": false,
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "pub-consent-1".into(),
                ..Default::default()
            },
            GetChallengeRequest
        );
        let resp = svc
            .get_consent_request(auth_context(&[SCOPE_IDENTITY_ADMIN]), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.challenge, "pub-consent-1");
        assert_eq!(resp.client_id, "pub-client-1");
        assert_eq!(resp.subject, "subject-1");
        assert!(!resp.skip);
        assert!(
            matches!(mock.take_calls().as_slice(), [Call::GetConsent(c)] if c == "consent-challenge-1")
        );
    }

    #[tokio::test]
    async fn get_consent_request_backfills_mapping_for_unmapped_subject() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "consent-challenge-1",
            "client": { "client_id": "client-1", "client_name": "App" },
            "subject": "ory-unmapped-subject",
            "skip": false,
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "pub-consent-1".into(),
                ..Default::default()
            },
            GetChallengeRequest
        );
        let resp = svc
            .get_consent_request(auth_context(&[SCOPE_IDENTITY_ADMIN]), req)
            .await
            .unwrap()
            .body;
        assert!(
            Ulid::from_string(&resp.subject).is_ok(),
            "subject should be a minted public ULID, got {}",
            resp.subject
        );
    }

    #[tokio::test]
    async fn get_consent_request_rejects_missing_scope() {
        let mock = Arc::new(MockConsentHydra::default());
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "pub-consent-1".into(),
                ..Default::default()
            },
            GetChallengeRequest
        );
        let err = svc
            .get_consent_request(request_context(), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn get_consent_request_maps_ory_error() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Err(OryClientError::Ory {
            status: 404,
            message: "not found".into(),
        }));
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "pub-consent-1".into(),
                ..Default::default()
            },
            GetChallengeRequest
        );
        let err = svc
            .get_consent_request(auth_context(&[SCOPE_TENANT_ADMIN]), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn accept_consent_happy_path() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "consent-challenge-2",
            "client": { "client_id": "client-1" },
            "subject": "ory-subject-1",
            "requested_scope": ["openid"],
        })));
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/callback",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "pub-consent-2".into(),
                grant_scope: vec!["openid".into()],
                remember: true,
                ..Default::default()
            },
            AcceptConsentRequest
        );
        let resp = svc
            .accept_consent(auth_context(&[SCOPE_IDENTITY_ADMIN]), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.redirect_to, "https://example.com/callback");
        let calls = mock.take_calls();
        assert!(matches!(
            calls.as_slice(),
            [Call::GetConsent(_), Call::AcceptConsent(c)] if c == "consent-challenge-2"
        ));
    }

    #[tokio::test]
    async fn accept_consent_injects_identity_id_claim() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "consent-challenge-2",
            "client": { "client_id": "client-1" },
            "subject": "ory-subject-1",
            "requested_scope": ["openid"],
        })));
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/callback",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "pub-consent-2".into(),
                grant_scope: vec!["openid".into()],
                ..Default::default()
            },
            AcceptConsentRequest
        );
        svc.accept_consent(auth_context(&[SCOPE_IDENTITY_ADMIN]), req)
            .await
            .unwrap();
        let bodies = mock.take_accept_bodies();
        assert_eq!(bodies.len(), 1);
        assert_eq!(
            bodies[0]["session"]["id_token"]["identity_id"],
            "subject-1"
        );
    }

    #[tokio::test]
    async fn accept_consent_preserves_caller_supplied_identity_id() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "consent-challenge-2",
            "client": { "client_id": "client-1" },
            "subject": "ory-subject-1",
            "requested_scope": ["openid"],
        })));
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/callback",
        })));
        let svc = service(mock.clone());
        let session: buffa_types::google::protobuf::Struct = serde_json::from_value(json!({
            "id_token": { "identity_id": "caller-supplied", "email": "a@example.com" }
        }))
        .unwrap();
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "pub-consent-2".into(),
                grant_scope: vec!["openid".into()],
                session: session.into(),
                ..Default::default()
            },
            AcceptConsentRequest
        );
        svc.accept_consent(auth_context(&[SCOPE_IDENTITY_ADMIN]), req)
            .await
            .unwrap();
        let bodies = mock.take_accept_bodies();
        assert_eq!(bodies.len(), 1);
        assert_eq!(
            bodies[0]["session"]["id_token"]["identity_id"],
            "caller-supplied"
        );
        assert_eq!(
            bodies[0]["session"]["id_token"]["email"],
            "a@example.com"
        );
    }

    #[tokio::test]
    async fn accept_consent_succeeds_for_unmapped_subject() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "consent-challenge-2",
            "client": { "client_id": "client-1" },
            "subject": "ory-unmapped-subject",
            "requested_scope": ["openid"],
        })));
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/callback",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "pub-consent-2".into(),
                grant_scope: vec!["openid".into()],
                ..Default::default()
            },
            AcceptConsentRequest
        );
        // An unmapped subject must not fail consent; the claim is skipped
        // (with a warning) and userinfo stays the fallback.
        let ctx = {
            let mut ctx = auth_context(&[SCOPE_TENANT_ADMIN]);
            let existing = ctx.extensions().get::<AuthContext>().unwrap().clone();
            ctx.extensions_mut().insert(AuthContext {
                subject: "subject-1".into(),
                ..existing
            });
            ctx
        };
        svc.accept_consent(ctx, req).await.unwrap();
        let bodies = mock.take_accept_bodies();
        assert_eq!(bodies.len(), 1);
        assert!(
            bodies[0].pointer("/session/id_token/identity_id").is_none(),
            "no identity_id claim for unmapped subject: {}",
            bodies[0]
        );
    }

    #[tokio::test]
    async fn accept_consent_maps_ory_error() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Err(OryClientError::Ory {
            status: 400,
            message: "bad request".into(),
        }));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "pub-consent-2".into(),
                grant_scope: vec!["openid".into()],
                ..Default::default()
            },
            AcceptConsentRequest
        );
        let err = svc
            .accept_consent(auth_context(&[SCOPE_TENANT_ADMIN]), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn accept_consent_rejects_excessive_scope() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "consent-challenge-2",
            "client": { "client_id": "client-1" },
            "subject": "ory-subject-1",
            "requested_scope": ["openid"],
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "pub-consent-2".into(),
                grant_scope: vec!["openid".into(), "admin".into()],
                ..Default::default()
            },
            AcceptConsentRequest
        );
        let err = svc
            .accept_consent(auth_context(&[SCOPE_IDENTITY_ADMIN]), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn accept_consent_allows_tenant_admin_for_other_subject() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "consent-challenge-2",
            "client": { "client_id": "client-1" },
            "subject": "ory-other-subject",
            "requested_scope": ["openid"],
        })));
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/callback",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "pub-consent-2".into(),
                grant_scope: vec!["openid".into()],
                ..Default::default()
            },
            AcceptConsentRequest
        );
        let ctx = {
            let mut ctx = auth_context(&[SCOPE_TENANT_ADMIN]);
            let existing = ctx.extensions().get::<AuthContext>().unwrap().clone();
            ctx.extensions_mut().insert(AuthContext {
                subject: "subject-1".into(),
                ..existing
            });
            ctx
        };
        svc.accept_consent(ctx, req).await.unwrap();
    }

    #[tokio::test]
    async fn accept_consent_rejects_subject_mismatch_without_admin() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "consent-challenge-2",
            "client": { "client_id": "client-1" },
            "subject": "ory-other-subject",
            "requested_scope": ["openid"],
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "pub-consent-2".into(),
                grant_scope: vec!["openid".into()],
                ..Default::default()
            },
            AcceptConsentRequest
        );
        let err = svc
            .accept_consent(auth_context(&[SCOPE_IDENTITY_ADMIN]), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn accept_consent_rejects_missing_admin_scope() {
        let mock = Arc::new(MockConsentHydra::default());
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "pub-consent-2".into(),
                grant_scope: vec!["openid".into()],
                ..Default::default()
            },
            AcceptConsentRequest
        );
        let err = svc
            .accept_consent(request_context(), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn reject_consent_happy_path() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/denied",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            RejectConsentRequest {
                challenge: "pub-consent-3".into(),
                error: "access_denied".into(),
                ..Default::default()
            },
            RejectConsentRequest
        );
        let resp = svc
            .reject_consent(auth_context(&[SCOPE_TENANT_ADMIN]), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.redirect_to, "https://example.com/denied");
        let calls = mock.take_calls();
        assert!(matches!(
            calls.as_slice(),
            [Call::RejectConsent(c)] if c == "consent-challenge-3"
        ));
    }

    #[tokio::test]
    async fn reject_consent_rejects_missing_admin_scope() {
        let mock = Arc::new(MockConsentHydra::default());
        let svc = service(mock.clone());
        svc_req!(
            req,
            RejectConsentRequest {
                challenge: "pub-consent-3".into(),
                error: "access_denied".into(),
                ..Default::default()
            },
            RejectConsentRequest
        );
        let err = svc
            .reject_consent(request_context(), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn reject_consent_maps_ory_error() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Err(OryClientError::Ory {
            status: 403,
            message: "forbidden".into(),
        }));
        let svc = service(mock.clone());
        svc_req!(
            req,
            RejectConsentRequest {
                challenge: "pub-consent-3".into(),
                error: "access_denied".into(),
                ..Default::default()
            },
            RejectConsentRequest
        );
        let err = svc
            .reject_consent(auth_context(&[SCOPE_TENANT_ADMIN]), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn get_logout_request_happy_path() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "logout-challenge-1",
            "subject": "ory-subject-1",
            "client": { "client_id": "client-1" },
            "request_url": "https://example.com/logout",
            "post_logout_redirect_uri": "https://example.com/after-logout",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "pub-logout-1".into(),
                ..Default::default()
            },
            GetChallengeRequest
        );
        let resp = svc
            .get_logout_request(request_context(), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.challenge, "pub-logout-1");
        assert_eq!(resp.subject, "subject-1");
        assert_eq!(resp.client_id, "pub-client-1");
        assert_eq!(resp.request_url, "https://example.com/logout");
        assert_eq!(
            resp.post_logout_redirect_uri,
            "https://example.com/after-logout"
        );
        assert!(
            matches!(mock.take_calls().as_slice(), [Call::GetLogout(c)] if c == "logout-challenge-1")
        );
    }

    #[tokio::test]
    async fn get_logout_request_maps_ory_error() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Err(OryClientError::Ory {
            status: 503,
            message: "unavailable".into(),
        }));
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "pub-logout-1".into(),
                ..Default::default()
            },
            GetChallengeRequest
        );
        let err = svc
            .get_logout_request(request_context(), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn accept_logout_happy_path() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/logout-callback",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptLogoutRequest {
                challenge: "pub-logout-2".into(),
                ..Default::default()
            },
            AcceptLogoutRequest
        );
        let resp = svc
            .accept_logout(request_context(), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.redirect_to, "https://example.com/logout-callback");
        let calls = mock.take_calls();
        assert!(matches!(
            calls.as_slice(),
            [Call::AcceptLogout(c)] if c == "logout-challenge-2"
        ));
    }

    #[tokio::test]
    async fn accept_logout_maps_ory_error() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Err(OryClientError::Http(
            reqwest::Client::new().get("not-a-url").build().unwrap_err(),
        )));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptLogoutRequest {
                challenge: "pub-logout-2".into(),
                ..Default::default()
            },
            AcceptLogoutRequest
        );
        let err = svc.accept_logout(request_context(), req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn reject_logout_happy_path() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/logout-rejected",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            RejectLogoutRequest {
                challenge: "pub-logout-3".into(),
                error: "invalid_request".into(),
                ..Default::default()
            },
            RejectLogoutRequest
        );
        let resp = svc
            .reject_logout(request_context(), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.redirect_to, "https://example.com/logout-rejected");
        let calls = mock.take_calls();
        assert!(matches!(
            calls.as_slice(),
            [Call::RejectLogout(c)] if c == "logout-challenge-3"
        ));
    }

    #[tokio::test]
    async fn reject_logout_maps_ory_error() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Err(OryClientError::Serialization(
            serde_json::from_str::<serde_json::Value>("not json").unwrap_err(),
        )));
        let svc = service(mock.clone());
        svc_req!(
            req,
            RejectLogoutRequest {
                challenge: "pub-logout-3".into(),
                error: "invalid_request".into(),
                ..Default::default()
            },
            RejectLogoutRequest
        );
        let err = svc.reject_logout(request_context(), req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
    }

    /// Regression: Hydra's post-login redirect delivers the raw Hydra
    /// consent_challenge to the consent app, so a lookup miss must pass the
    /// value through instead of failing with not_found (mirrors the
    /// login_challenge passthrough).
    #[tokio::test]
    async fn get_consent_request_passes_through_raw_hydra_challenge() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "raw-consent-challenge",
            "client": { "client_id": "client-1", "client_name": "App" },
            "subject": "ory-subject-1",
            "skip": false,
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "raw-consent-challenge".into(),
                ..Default::default()
            },
            GetChallengeRequest
        );
        let resp = svc
            .get_consent_request(auth_context(&[SCOPE_IDENTITY_ADMIN]), req)
            .await
            .unwrap()
            .body;
        // The raw challenge reaches Hydra verbatim...
        assert!(
            matches!(mock.take_calls().as_slice(), [Call::GetConsent(c)] if c == "raw-consent-challenge")
        );
        // ...while the response still exposes only a gateway-minted challenge.
        assert!(!resp.challenge.is_empty());
        assert_ne!(resp.challenge, "raw-consent-challenge");
        assert_eq!(resp.client_id, "pub-client-1");
        assert_eq!(resp.subject, "subject-1");
    }

    #[tokio::test]
    async fn accept_consent_passes_through_raw_hydra_challenge() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "raw-consent-accept",
            "client": { "client_id": "client-1" },
            "subject": "ory-subject-1",
            "requested_scope": ["openid"],
        })));
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/callback",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "raw-consent-accept".into(),
                grant_scope: vec!["openid".into()],
                ..Default::default()
            },
            AcceptConsentRequest
        );
        let resp = svc
            .accept_consent(auth_context(&[SCOPE_IDENTITY_ADMIN]), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.redirect_to, "https://example.com/callback");
        let calls = mock.take_calls();
        assert!(matches!(
            calls.as_slice(),
            [Call::GetConsent(g), Call::AcceptConsent(a)]
                if g == "raw-consent-accept" && a == "raw-consent-accept"
        ));
    }

    /// Regression: Hydra's redirect to the logout app carries the raw Hydra
    /// logout_challenge; the lookup miss must pass through, using the caller's
    /// tenant from the request context for id mapping.
    #[tokio::test]
    async fn get_logout_request_passes_through_raw_hydra_challenge() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "raw-logout-challenge",
            "subject": "ory-subject-1",
            "client": { "client_id": "client-1" },
            "request_url": "https://example.com/logout",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "raw-logout-challenge".into(),
                ..Default::default()
            },
            GetChallengeRequest
        );
        let resp = svc
            .get_logout_request(auth_context(&[]), req)
            .await
            .unwrap()
            .body;
        assert!(
            matches!(mock.take_calls().as_slice(), [Call::GetLogout(c)] if c == "raw-logout-challenge")
        );
        assert!(!resp.challenge.is_empty());
        assert_ne!(resp.challenge, "raw-logout-challenge");
        assert_eq!(resp.client_id, "pub-client-1");
        assert_eq!(resp.subject, "subject-1");
    }

    #[tokio::test]
    async fn accept_logout_passes_through_raw_hydra_challenge() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/logout-callback",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptLogoutRequest {
                challenge: "raw-logout-accept".into(),
                ..Default::default()
            },
            AcceptLogoutRequest
        );
        let resp = svc
            .accept_logout(request_context(), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.redirect_to, "https://example.com/logout-callback");
        let calls = mock.take_calls();
        assert!(matches!(
            calls.as_slice(),
            [Call::AcceptLogout(c)] if c == "raw-logout-accept"
        ));
    }

    #[tokio::test]
    async fn reject_logout_passes_through_raw_hydra_challenge() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/logout-rejected",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            RejectLogoutRequest {
                challenge: "raw-logout-reject".into(),
                error: "invalid_request".into(),
                ..Default::default()
            },
            RejectLogoutRequest
        );
        let resp = svc
            .reject_logout(request_context(), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.redirect_to, "https://example.com/logout-rejected");
        let calls = mock.take_calls();
        assert!(matches!(
            calls.as_slice(),
            [Call::RejectLogout(c)] if c == "raw-logout-reject"
        ));
    }

    #[tokio::test]
    async fn hydra_client_as_consent_hydra_delegates() {
        let client = Arc::new(HydraClient::new("http://localhost:1", "http://localhost:1").unwrap())
            as Arc<dyn ConsentHydra>;
        assert!(client.get_consent_request("challenge").await.is_err());
        assert!(
            client
                .accept_consent_request("challenge", json!({}))
                .await
                .is_err()
        );
        assert!(
            client
                .reject_consent_request("challenge", json!({}))
                .await
                .is_err()
        );
        assert!(client.get_logout_request("challenge").await.is_err());
        assert!(
            client
                .accept_logout_request("challenge", json!({}))
                .await
                .is_err()
        );
        assert!(
            client
                .reject_logout_request("challenge", json!({}))
                .await
                .is_err()
        );
    }
}
