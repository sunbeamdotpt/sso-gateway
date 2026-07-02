use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;

use crate::auth::{AuthContext, SCOPE_IDENTITY_ADMIN, SCOPE_TENANT_ADMIN};
use crate::proto::iam::v1::{
    AcceptConsentRequest, AcceptLogoutRequest, ConsentRequest, ConsentResponse,
    GetChallengeRequest, LogoutRequest, LogoutResponse, OAuth2ConsentService, RejectConsentRequest,
    RejectLogoutRequest,
};

use super::oauth2_consent_mapper::{
    accept_consent_request_to_json, accept_logout_request_to_json, ory_consent_request_to_proto,
    ory_consent_response_to_proto, ory_logout_request_to_proto, ory_logout_response_to_proto,
    reject_consent_request_to_json, reject_logout_request_to_json,
};

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
}

impl OAuth2ConsentServiceImpl {
    pub fn new(hydra: Arc<HydraClient>) -> Self {
        Self {
            hydra: hydra as Arc<dyn ConsentHydra>,
        }
    }
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

#[allow(refining_impl_trait)]
impl OAuth2ConsentService for OAuth2ConsentServiceImpl {
    #[instrument(skip(self, request))]
    async fn get_consent_request(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetChallengeRequest>,
    ) -> ServiceResult<ConsentRequest> {
        require_consent_admin(&ctx)?;
        let req = request.to_owned_message();
        let value = self
            .hydra
            .get_consent_request(&req.challenge)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_consent_request_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn accept_consent(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AcceptConsentRequest>,
    ) -> ServiceResult<ConsentResponse> {
        require_consent_admin(&ctx)?;
        let req = request.to_owned_message();
        let challenge = req.challenge.clone();

        // Fetch the consent request first to enforce that the challenge exists,
        // has not been handled yet, and to obtain the requested scopes/subject.
        let consent_value = self
            .hydra
            .get_consent_request(&challenge)
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
        if auth.subject != consent.subject && !is_tenant_admin {
            return Err(ServiceError::PermissionDenied(
                "cannot accept consent for another subject".into(),
            )
            .into());
        }

        let body = accept_consent_request_to_json(&req);
        let value = self
            .hydra
            .accept_consent_request(&challenge, body)
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
        let req = request.to_owned_message();
        let challenge = req.challenge.clone();
        let body = reject_consent_request_to_json(&req);
        let value = self
            .hydra
            .reject_consent_request(&challenge, body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_consent_response_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn get_logout_request(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetChallengeRequest>,
    ) -> ServiceResult<LogoutRequest> {
        let req = request.to_owned_message();
        let value = self
            .hydra
            .get_logout_request(&req.challenge)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_logout_request_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn accept_logout(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, AcceptLogoutRequest>,
    ) -> ServiceResult<LogoutResponse> {
        let req = request.to_owned_message();
        let challenge = req.challenge.clone();
        let body = accept_logout_request_to_json(&req);
        let value = self
            .hydra
            .accept_logout_request(&challenge, body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_logout_response_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn reject_logout(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RejectLogoutRequest>,
    ) -> ServiceResult<LogoutResponse> {
        let req = request.to_owned_message();
        let challenge = req.challenge.clone();
        let body = reject_logout_request_to_json(&req);
        let value = self
            .hydra
            .reject_logout_request(&challenge, body)
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
    }
}

#[cfg(test)]
mod tests {
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

    use crate::auth::{AuthContext, SCOPE_IDENTITY_ADMIN, SCOPE_TENANT_ADMIN};
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
            _body: Value,
        ) -> Result<Value, OryClientError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::AcceptConsent(challenge.to_string()));
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

    fn service(hydra: Arc<dyn ConsentHydra>) -> OAuth2ConsentServiceImpl {
        OAuth2ConsentServiceImpl { hydra }
    }

    fn request_context() -> RequestContext {
        RequestContext::new(HeaderMap::new())
    }

    fn auth_context(scopes: &[&str]) -> RequestContext {
        let mut ctx = RequestContext::new(HeaderMap::new());
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "subject-1".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token_hash: "hash".into(),
        });
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

    #[test]
    fn oauth2_consent_service_impl_new_stores_hydra() {
        let hydra = Arc::new(HydraClient::new("http://localhost:1", "http://localhost:1").unwrap());
        let service = OAuth2ConsentServiceImpl::new(hydra);
        let _cloned = service.clone();
    }

    #[tokio::test]
    async fn get_consent_request_happy_path() {
        let mock = Arc::new(MockConsentHydra::default());
        mock.queue(Ok(serde_json::json!({
            "challenge": "consent-challenge-1",
            "client": { "client_id": "client-1", "client_name": "App" },
            "subject": "subject-1",
            "skip": false,
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "consent-challenge-1".into(),
                ..Default::default()
            },
            GetChallengeRequest
        );
        let resp = svc
            .get_consent_request(auth_context(&[SCOPE_IDENTITY_ADMIN]), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.challenge, "consent-challenge-1");
        assert_eq!(resp.client_id, "client-1");
        assert_eq!(resp.subject, "subject-1");
        assert!(!resp.skip);
        assert!(
            matches!(mock.take_calls().as_slice(), [Call::GetConsent(c)] if c == "consent-challenge-1")
        );
    }

    #[tokio::test]
    async fn get_consent_request_rejects_missing_scope() {
        let mock = Arc::new(MockConsentHydra::default());
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "consent-challenge-1".into(),
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
                challenge: "missing".into(),
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
            "subject": "subject-1",
            "requested_scope": ["openid"],
        })));
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/callback",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "consent-challenge-2".into(),
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
                challenge: "bad-challenge".into(),
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
            "subject": "subject-1",
            "requested_scope": ["openid"],
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "consent-challenge-2".into(),
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
            "subject": "other-subject",
            "requested_scope": ["openid"],
        })));
        mock.queue(Ok(serde_json::json!({
            "redirect_to": "https://example.com/callback",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "consent-challenge-2".into(),
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
            "subject": "other-subject",
            "requested_scope": ["openid"],
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            AcceptConsentRequest {
                challenge: "consent-challenge-2".into(),
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
                challenge: "consent-challenge-2".into(),
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
                challenge: "consent-challenge-3".into(),
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
                challenge: "consent-challenge-3".into(),
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
                challenge: "forbidden-challenge".into(),
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
            "subject": "subject-1",
            "client": { "client_id": "client-1" },
            "request_url": "https://example.com/logout",
            "post_logout_redirect_uri": "https://example.com/after-logout",
        })));
        let svc = service(mock.clone());
        svc_req!(
            req,
            GetChallengeRequest {
                challenge: "logout-challenge-1".into(),
                ..Default::default()
            },
            GetChallengeRequest
        );
        let resp = svc
            .get_logout_request(request_context(), req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.challenge, "logout-challenge-1");
        assert_eq!(resp.subject, "subject-1");
        assert_eq!(resp.client_id, "client-1");
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
                challenge: "missing-logout".into(),
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
                challenge: "logout-challenge-2".into(),
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
                challenge: "network-error".into(),
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
                challenge: "logout-challenge-3".into(),
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
                challenge: "bad-response".into(),
                error: "invalid_request".into(),
                ..Default::default()
            },
            RejectLogoutRequest
        );
        let err = svc.reject_logout(request_context(), req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
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
