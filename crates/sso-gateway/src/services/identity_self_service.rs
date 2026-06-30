use std::sync::Arc;

use async_trait::async_trait;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::{error::OryClientError, kratos::KratosClient};
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;

use crate::middleware::TenantId;
use crate::proto::iam::v1::{
    BrowserSession, CreateLoginFlowRequest, CreateLogoutFlowRequest, CreateRecoveryFlowRequest,
    CreateRegistrationFlowRequest, CreateSettingsFlowRequest, CreateVerificationFlowRequest,
    FlowError, GetFlowErrorRequest, GetFlowRequest, IdentitySelfService, LogoutFlow,
    SelfServiceFlow, SubmitFlowRequest, SubmitLogoutFlowRequest, ToSessionRequest,
    WebAuthnJsResponse,
};
use buffa_types::google::protobuf::Empty;

use super::identity_self_service_mapper::{
    ory_flow_error_to_proto, ory_flow_to_proto, ory_logout_flow_to_proto, ory_session_to_proto,
    ory_webauthn_js_to_proto, proto_struct_to_json,
};

/// Async trait abstracting the Kratos self-service operations used by this
/// service. Keeps the service implementation decoupled from the concrete HTTP
/// client so unit tests can inject stubs.
#[async_trait]
pub trait KratosSelfService: Send + Sync {
    async fn to_session(
        &self,
        cookie: Option<&str>,
        token: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn get_login_flow(&self, id: &str, cookie: Option<&str>) -> Result<Value, OryClientError>;

    async fn get_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn get_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn get_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn get_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn submit_login_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError>;

    async fn submit_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError>;

    async fn submit_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError>;

    async fn submit_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError>;

    async fn submit_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError>;

    async fn create_login_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn create_registration_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn create_settings_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn create_recovery_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn create_verification_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn create_logout_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn submit_logout_flow(
        &self,
        token: &str,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<(), OryClientError>;

    async fn get_flow_error(&self, id: &str) -> Result<Value, OryClientError>;

    async fn get_webauthn_js(&self) -> Result<String, OryClientError>;
}

#[async_trait]
impl KratosSelfService for KratosClient {
    async fn to_session(
        &self,
        cookie: Option<&str>,
        token: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.to_session(cookie, token).await
    }

    async fn get_login_flow(&self, id: &str, cookie: Option<&str>) -> Result<Value, OryClientError> {
        self.get_login_flow(id, cookie).await
    }

    async fn get_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.get_registration_flow(id, cookie).await
    }

    async fn get_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.get_settings_flow(id, cookie).await
    }

    async fn get_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.get_recovery_flow(id, cookie).await
    }

    async fn get_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.get_verification_flow(id, cookie).await
    }

    async fn submit_login_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.submit_login_flow(id, cookie, body).await
    }

    async fn submit_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.submit_registration_flow(id, cookie, body).await
    }

    async fn submit_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.submit_settings_flow(id, cookie, body).await
    }

    async fn submit_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.submit_recovery_flow(id, cookie, body).await
    }

    async fn submit_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.submit_verification_flow(id, cookie, body).await
    }

    async fn create_login_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_login_browser_flow(return_to, cookie).await
    }

    async fn create_registration_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_registration_browser_flow(return_to, cookie).await
    }

    async fn create_settings_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_settings_browser_flow(return_to, cookie).await
    }

    async fn create_recovery_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_recovery_browser_flow(return_to, cookie).await
    }

    async fn create_verification_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_verification_flow(return_to, cookie).await
    }

    async fn create_logout_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.create_logout_flow(return_to, cookie).await
    }

    async fn submit_logout_flow(
        &self,
        token: &str,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<(), OryClientError> {
        self.submit_logout_flow(token, return_to, cookie).await
    }

    async fn get_flow_error(&self, id: &str) -> Result<Value, OryClientError> {
        self.get_flow_error(id).await
    }

    async fn get_webauthn_js(&self) -> Result<String, OryClientError> {
        self.get_webauthn_js().await
    }
}

#[derive(Clone)]
pub struct IdentitySelfServiceImpl {
    kratos: Arc<dyn KratosSelfService>,
}

impl IdentitySelfServiceImpl {
    pub fn new(kratos: Arc<KratosClient>) -> Self {
        Self {
            kratos: kratos as Arc<dyn KratosSelfService>,
        }
    }
}

fn cookie_from_context(ctx: &RequestContext) -> Option<String> {
    ctx.headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

fn tenant_from_context(ctx: &RequestContext) -> String {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .unwrap_or_default()
}

#[allow(refining_impl_trait)]
impl IdentitySelfService for IdentitySelfServiceImpl {
    #[instrument(skip(self, request))]
    async fn to_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ToSessionRequest>,
    ) -> ServiceResult<BrowserSession> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let token = if req.session_token.is_empty() {
            None
        } else {
            Some(req.session_token.as_str())
        };

        let session = self
            .kratos
            .to_session(cookie.as_deref(), token)
            .await
            .map_err(map_ory_error)?;

        let mut proto = ory_session_to_proto(&session);
        proto.tenant_id = tenant_from_context(&ctx);
        Ok(Response::new(proto))
    }

    #[instrument(skip(self, request))]
    async fn get_login_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let flow = self
            .kratos
            .get_login_flow(&req.id, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn get_registration_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let flow = self
            .kratos
            .get_registration_flow(&req.id, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn get_settings_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let flow = self
            .kratos
            .get_settings_flow(&req.id, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn get_recovery_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let flow = self
            .kratos
            .get_recovery_flow(&req.id, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn get_verification_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let flow = self
            .kratos
            .get_verification_flow(&req.id, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn submit_login_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let body = proto_struct_to_json(req.body.as_option());
        let flow = self
            .kratos
            .submit_login_flow(&req.id, cookie.as_deref(), body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn submit_registration_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let body = proto_struct_to_json(req.body.as_option());
        let flow = self
            .kratos
            .submit_registration_flow(&req.id, cookie.as_deref(), body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn submit_settings_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let body = proto_struct_to_json(req.body.as_option());
        let flow = self
            .kratos
            .submit_settings_flow(&req.id, cookie.as_deref(), body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn submit_recovery_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let body = proto_struct_to_json(req.body.as_option());
        let flow = self
            .kratos
            .submit_recovery_flow(&req.id, cookie.as_deref(), body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn submit_verification_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let body = proto_struct_to_json(req.body.as_option());
        let flow = self
            .kratos
            .submit_verification_flow(&req.id, cookie.as_deref(), body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn create_login_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateLoginFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let return_to = if req.return_to.is_empty() {
            None
        } else {
            Some(req.return_to.as_str())
        };
        let flow = self
            .kratos
            .create_login_browser_flow(return_to, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn create_registration_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateRegistrationFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let return_to = if req.return_to.is_empty() {
            None
        } else {
            Some(req.return_to.as_str())
        };
        let flow = self
            .kratos
            .create_registration_browser_flow(return_to, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn create_settings_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateSettingsFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let return_to = if req.return_to.is_empty() {
            None
        } else {
            Some(req.return_to.as_str())
        };
        let flow = self
            .kratos
            .create_settings_browser_flow(return_to, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn create_recovery_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateRecoveryFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let return_to = if req.return_to.is_empty() {
            None
        } else {
            Some(req.return_to.as_str())
        };
        let flow = self
            .kratos
            .create_recovery_browser_flow(return_to, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn create_logout_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateLogoutFlowRequest>,
    ) -> ServiceResult<LogoutFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let return_to = if req.return_to.is_empty() {
            None
        } else {
            Some(req.return_to.as_str())
        };
        let flow = self
            .kratos
            .create_logout_flow(return_to, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_logout_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn submit_logout_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitLogoutFlowRequest>,
    ) -> ServiceResult<Empty> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let return_to = if req.return_to.is_empty() {
            None
        } else {
            Some(req.return_to.as_str())
        };
        self.kratos
            .submit_logout_flow(&req.token, return_to, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(Empty::default()))
    }

    #[instrument(skip(self, request))]
    async fn create_verification_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateVerificationFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let return_to = if req.return_to.is_empty() {
            None
        } else {
            Some(req.return_to.as_str())
        };
        let flow = self
            .kratos
            .create_verification_flow(return_to, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_to_proto(&flow)))
    }

    #[instrument(skip(self, request))]
    async fn get_flow_error(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetFlowErrorRequest>,
    ) -> ServiceResult<FlowError> {
        let req = request.to_owned_message();
        let error = self
            .kratos
            .get_flow_error(&req.id)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_flow_error_to_proto(&error)))
    }

    #[instrument(skip(self))]
    async fn get_web_authn_java_script(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, Empty>,
    ) -> ServiceResult<WebAuthnJsResponse> {
        let content = self.kratos.get_webauthn_js().await.map_err(map_ory_error)?;
        Ok(Response::new(ory_webauthn_js_to_proto(&content)))
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
            ServiceError::Unavailable("upstream identity service unreachable".into())
        }
        OryClientError::Serialization(_) | OryClientError::InvalidResponse(_) => {
            ServiceError::Internal("invalid upstream response".into())
        }
        OryClientError::MissingTenant => ServiceError::Unauthenticated("missing tenant".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use buffa::{bytes::Bytes, HasMessageView, Message, MessageView};
    use connectrpc::{ErrorCode, RequestContext, ServiceRequest};
    use http::HeaderMap;
    use serde_json::{json, Value};
    use sso_ory_client::{error::OryClientError, kratos::KratosClient};
    use sunbeam_g2v::error::ServiceError;

    use crate::middleware::TenantId;
    use crate::proto::iam::v1::{
        CreateLoginFlowRequest, CreateLogoutFlowRequest, CreateRecoveryFlowRequest,
        CreateRegistrationFlowRequest, CreateSettingsFlowRequest, CreateVerificationFlowRequest,
        GetFlowErrorRequest, GetFlowRequest, IdentitySelfService, SubmitFlowRequest,
        SubmitLogoutFlowRequest, ToSessionRequest,
    };

    use super::{
        cookie_from_context, map_ory_error, tenant_from_context, IdentitySelfServiceImpl,
        KratosSelfService,
    };

    fn request_context_with_cookie(cookie: &str) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie.parse().unwrap());
        RequestContext::new(headers)
    }

    fn request_context_without_cookie() -> RequestContext {
        RequestContext::new(HeaderMap::new())
    }

    fn request_context_with_tenant(tenant: &str) -> RequestContext {
        let mut ctx = RequestContext::new(HeaderMap::new());
        ctx.extensions_mut().insert(TenantId(tenant.to_string()));
        ctx
    }

    fn service_request<Req>(msg: Req) -> ServiceRequest<'static, Req>
    where
        Req: Message + HasMessageView,
    {
        let bytes = Bytes::from(msg.encode_to_vec());
        let bytes: &'static Bytes = Box::leak(Box::new(bytes));
        let view = Req::View::decode_view(bytes).unwrap();
        let view: &'static Req::View<'static> = Box::leak(Box::new(view));
        ServiceRequest::from_parts(view, bytes)
    }

    fn sample_flow() -> Value {
        json!({
            "id": "flow-1",
            "type": "login",
            "state": "choose_method"
        })
    }

    fn sample_session() -> Value {
        json!({
            "id": "session-1",
            "active": true,
            "identity": { "id": "identity-1" }
        })
    }

    fn sample_logout_flow() -> Value {
        json!({
            "id": "logout-1",
            "logout_url": "http://logout",
            "logout_token": "token-1"
        })
    }

    fn sample_flow_error() -> Value {
        json!({ "id": "error-1", "error": "oops" })
    }

    fn sample_webauthn_js() -> String {
        "console.log('webauthn');".to_string()
    }

    #[derive(Default, Clone)]
    struct FakeKratos {
        session: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        flow: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        logout_flow: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        logout_submit: Arc<Mutex<Option<Result<(), OryClientError>>>>,
        flow_error: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        webauthn_js: Arc<Mutex<Option<Result<String, OryClientError>>>>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl FakeKratos {
        fn take_flow(&self) -> Result<Value, OryClientError> {
            self.flow
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        fn reseed_flow(&self, value: Value) {
            *self.flow.lock().unwrap() = Some(Ok(value));
        }

        fn reseed_flow_error(&self, status: u16, message: &str) {
            *self.flow.lock().unwrap() = Some(Err(OryClientError::Ory {
                status,
                message: message.to_string(),
            }));
        }

        fn record(&self, call: impl Into<String>) {
            self.calls.lock().unwrap().push(call.into());
        }
    }

    #[async_trait::async_trait]
    impl KratosSelfService for FakeKratos {
        async fn to_session(
            &self,
            cookie: Option<&str>,
            token: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "to_session(cookie={:?}, token={:?})",
                cookie, token
            ));
            self.session
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        async fn get_login_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!("get_login_flow(id={id}, cookie={:?})", cookie));
            self.take_flow()
        }

        async fn get_registration_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "get_registration_flow(id={id}, cookie={:?})",
                cookie
            ));
            self.take_flow()
        }

        async fn get_settings_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!("get_settings_flow(id={id}, cookie={:?})", cookie));
            self.take_flow()
        }

        async fn get_recovery_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!("get_recovery_flow(id={id}, cookie={:?})", cookie));
            self.take_flow()
        }

        async fn get_verification_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "get_verification_flow(id={id}, cookie={:?})",
                cookie
            ));
            self.take_flow()
        }

        async fn submit_login_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
            body: Value,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "submit_login_flow(id={id}, cookie={:?}, body={body})",
                cookie
            ));
            self.take_flow()
        }

        async fn submit_registration_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
            body: Value,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "submit_registration_flow(id={id}, cookie={:?}, body={body})",
                cookie
            ));
            self.take_flow()
        }

        async fn submit_settings_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
            body: Value,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "submit_settings_flow(id={id}, cookie={:?}, body={body})",
                cookie
            ));
            self.take_flow()
        }

        async fn submit_recovery_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
            body: Value,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "submit_recovery_flow(id={id}, cookie={:?}, body={body})",
                cookie
            ));
            self.take_flow()
        }

        async fn submit_verification_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
            body: Value,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "submit_verification_flow(id={id}, cookie={:?}, body={body})",
                cookie
            ));
            self.take_flow()
        }

        async fn create_login_browser_flow(
            &self,
            return_to: Option<&str>,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "create_login_browser_flow(return_to={:?}, cookie={:?})",
                return_to, cookie
            ));
            self.take_flow()
        }

        async fn create_registration_browser_flow(
            &self,
            return_to: Option<&str>,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "create_registration_browser_flow(return_to={:?}, cookie={:?})",
                return_to, cookie
            ));
            self.take_flow()
        }

        async fn create_settings_browser_flow(
            &self,
            return_to: Option<&str>,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "create_settings_browser_flow(return_to={:?}, cookie={:?})",
                return_to, cookie
            ));
            self.take_flow()
        }

        async fn create_recovery_browser_flow(
            &self,
            return_to: Option<&str>,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "create_recovery_browser_flow(return_to={:?}, cookie={:?})",
                return_to, cookie
            ));
            self.take_flow()
        }

        async fn create_verification_flow(
            &self,
            return_to: Option<&str>,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "create_verification_flow(return_to={:?}, cookie={:?})",
                return_to, cookie
            ));
            self.take_flow()
        }

        async fn create_logout_flow(
            &self,
            return_to: Option<&str>,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "create_logout_flow(return_to={:?}, cookie={:?})",
                return_to, cookie
            ));
            self.logout_flow
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        async fn submit_logout_flow(
            &self,
            token: &str,
            return_to: Option<&str>,
            cookie: Option<&str>,
        ) -> Result<(), OryClientError> {
            self.record(format!(
                "submit_logout_flow(token={token}, return_to={:?}, cookie={:?})",
                return_to, cookie
            ));
            self.logout_submit
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        async fn get_flow_error(&self, id: &str) -> Result<Value, OryClientError> {
            self.record(format!("get_flow_error(id={id})"));
            self.flow_error
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        async fn get_webauthn_js(&self) -> Result<String, OryClientError> {
            self.record("get_webauthn_js()".to_string());
            self.webauthn_js
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }
    }

    fn service(kratos: FakeKratos) -> IdentitySelfServiceImpl {
        IdentitySelfServiceImpl {
            kratos: Arc::new(kratos),
        }
    }

    #[test]
    fn new_stores_kratos_client() {
        let kratos = Arc::new(KratosClient::new("http://localhost:4434").unwrap());
        let svc = IdentitySelfServiceImpl::new(kratos.clone());
        // Field is now a trait object; just verify the service was created.
        assert_eq!(Arc::strong_count(&kratos), 2);
        let _ = svc;
    }

    #[test]
    fn cookie_from_context_extracts_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "session=abc".parse().unwrap());
        let ctx = RequestContext::new(headers);
        assert_eq!(cookie_from_context(&ctx), Some("session=abc".to_string()));
    }

    #[test]
    fn cookie_from_context_returns_none_when_missing() {
        let ctx = RequestContext::new(HeaderMap::new());
        assert_eq!(cookie_from_context(&ctx), None);
    }

    #[test]
    fn tenant_from_context_extracts_tenant_id() {
        let mut ctx = RequestContext::new(HeaderMap::new());
        ctx.extensions_mut().insert(TenantId("tenant-1".to_string()));
        assert_eq!(tenant_from_context(&ctx), "tenant-1");
    }

    #[test]
    fn tenant_from_context_defaults_to_empty() {
        let ctx = RequestContext::new(HeaderMap::new());
        assert_eq!(tenant_from_context(&ctx), "");
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
        let missing = map_ory_error(OryClientError::MissingTenant);

        assert!(matches!(http, ServiceError::Unavailable(_)));
        assert!(matches!(url, ServiceError::Unavailable(_)));
        assert!(matches!(ser, ServiceError::Internal(_)));
        assert!(matches!(missing, ServiceError::Unauthenticated(_)));
    }

    #[test]
    fn map_ory_error_invalid_response() {
        let err = map_ory_error(OryClientError::InvalidResponse("bad json".into()));
        assert!(matches!(err, ServiceError::Internal(_)));
    }

    #[tokio::test]
    async fn to_session_happy_path() {
        let fake = FakeKratos {
            session: Arc::new(Mutex::new(Some(Ok(sample_session())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_tenant("tenant-1");
        let req = service_request(ToSessionRequest {
            session_token: "token-1".to_string(),
            ..Default::default()
        });

        let resp = svc.to_session(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "session-1");
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
        assert_eq!(
            fake.calls.lock().unwrap()[0],
            "to_session(cookie=None, token=Some(\"token-1\"))"
        );
    }

    #[tokio::test]
    async fn to_session_error_path() {
        let fake = FakeKratos {
            session: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 401,
                message: "no session".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(ToSessionRequest::default());

        let err = svc.to_session(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Unauthenticated);
    }

    #[tokio::test]
    async fn get_login_flow_happy_path() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(GetFlowRequest {
            id: "flow-1".to_string(),
            ..Default::default()
        });

        let resp = svc.get_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_eq!(
            fake.calls.lock().unwrap()[0],
            "get_login_flow(id=flow-1, cookie=Some(\"session=abc\"))"
        );
    }

    #[tokio::test]
    async fn get_login_flow_error_path() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 404,
                message: "not found".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(GetFlowRequest {
            id: "missing".to_string(),
            ..Default::default()
        });

        let err = svc.get_login_flow(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn submit_login_flow_happy_path() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(SubmitFlowRequest {
            id: "flow-1".to_string(),
            ..Default::default()
        });

        let resp = svc.submit_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert!(
            fake.calls.lock().unwrap()[0].starts_with("submit_login_flow(id=flow-1, cookie=Some(")
        );
    }

    #[tokio::test]
    async fn submit_login_flow_error_path() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 400,
                message: "invalid".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(SubmitFlowRequest {
            id: "flow-1".to_string(),
            ..Default::default()
        });

        let err = svc.submit_login_flow(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn create_login_flow_happy_path() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(CreateLoginFlowRequest {
            return_to: "http://return".to_string(),
            ..Default::default()
        });

        let resp = svc.create_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert!(
            fake.calls.lock().unwrap()[0]
                .starts_with("create_login_browser_flow(return_to=Some(\"http://return\"), cookie=Some(")
        );
    }

    #[tokio::test]
    async fn create_login_flow_error_path() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 503,
                message: "down".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(CreateLoginFlowRequest::default());

        let err = svc.create_login_flow(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn create_logout_flow_happy_path() {
        let fake = FakeKratos {
            logout_flow: Arc::new(Mutex::new(Some(Ok(sample_logout_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(CreateLogoutFlowRequest {
            return_to: "http://return".to_string(),
            ..Default::default()
        });

        let resp = svc.create_logout_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.logout_token, "token-1");
        assert!(
            fake.calls.lock().unwrap()[0]
                .starts_with("create_logout_flow(return_to=Some(\"http://return\"), cookie=Some(")
        );
    }

    #[tokio::test]
    async fn create_logout_flow_error_path() {
        let fake = FakeKratos {
            logout_flow: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 401,
                message: "unauthenticated".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(CreateLogoutFlowRequest::default());

        let err = svc.create_logout_flow(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Unauthenticated);
    }

    #[tokio::test]
    async fn submit_logout_flow_happy_path() {
        let fake = FakeKratos {
            logout_submit: Arc::new(Mutex::new(Some(Ok(())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(SubmitLogoutFlowRequest {
            id: "logout-1".to_string(),
            token: "token-1".to_string(),
            return_to: "http://return".to_string(),
            ..Default::default()
        });

        svc.submit_logout_flow(ctx, req).await.unwrap();
        assert!(
            fake.calls.lock().unwrap()[0]
                .starts_with("submit_logout_flow(token=token-1, return_to=Some(\"http://return\"), cookie=Some(")
        );
    }

    #[tokio::test]
    async fn submit_logout_flow_error_path() {
        let fake = FakeKratos {
            logout_submit: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 400,
                message: "bad token".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(SubmitLogoutFlowRequest {
            id: "logout-1".to_string(),
            token: "token-1".to_string(),
            ..Default::default()
        });

        let err = svc.submit_logout_flow(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn get_flow_error_happy_path() {
        let fake = FakeKratos {
            flow_error: Arc::new(Mutex::new(Some(Ok(sample_flow_error())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_without_cookie();
        let req = service_request(GetFlowErrorRequest {
            id: "error-1".to_string(),
            ..Default::default()
        });

        let resp = svc.get_flow_error(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "error-1");
        assert_eq!(fake.calls.lock().unwrap()[0], "get_flow_error(id=error-1)");
    }

    #[tokio::test]
    async fn get_flow_error_error_path() {
        let fake = FakeKratos {
            flow_error: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 404,
                message: "not found".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(GetFlowErrorRequest {
            id: "missing".to_string(),
            ..Default::default()
        });

        let err = svc.get_flow_error(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn get_web_authn_java_script_happy_path() {
        let fake = FakeKratos {
            webauthn_js: Arc::new(Mutex::new(Some(Ok(sample_webauthn_js())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_without_cookie();
        let req = service_request(buffa_types::google::protobuf::Empty::default());

        let resp = svc.get_web_authn_java_script(ctx, req).await.unwrap();
        assert_eq!(resp.body.content, "console.log('webauthn');");
        assert_eq!(fake.calls.lock().unwrap()[0], "get_webauthn_js()");
    }

    #[tokio::test]
    async fn get_web_authn_java_script_error_path() {
        let fake = FakeKratos {
            webauthn_js: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 500,
                message: "fail".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(buffa_types::google::protobuf::Empty::default());

        let err = svc.get_web_authn_java_script(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
    }

    macro_rules! assert_flow_call {
        ($fake:expr, $prefix:literal) => {
            assert!(
                $fake.calls.lock().unwrap().last().unwrap().starts_with($prefix),
                "expected call starting with {}, got {}",
                $prefix,
                $fake.calls.lock().unwrap().last().unwrap()
            );
        };
    }

    #[tokio::test]
    async fn registration_flow_methods_cover_happy_and_error() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_tenant("tenant-1");

        let get_req = service_request(GetFlowRequest {
            id: "registration-flow".to_string(),
            ..Default::default()
        });
        let resp = svc.get_registration_flow(ctx.clone(), get_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "get_registration_flow(id=registration-flow, cookie=None)");

        fake.reseed_flow(sample_flow());
        let submit_req = service_request(SubmitFlowRequest {
            id: "registration-flow".to_string(),
            ..Default::default()
        });
        let resp = svc
            .submit_registration_flow(ctx.clone(), submit_req)
            .await
            .unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "submit_registration_flow(id=registration-flow, cookie=None, body=");

        fake.reseed_flow(sample_flow());
        let create_req = service_request(CreateRegistrationFlowRequest {
            return_to: "http://return".to_string(),
            ..Default::default()
        });
        let resp = svc.create_registration_flow(ctx, create_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "create_registration_browser_flow(return_to=Some(\"http://return\"), cookie=None)");
    }

    #[tokio::test]
    async fn settings_flow_methods_cover_happy_and_error() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_tenant("tenant-1");

        let get_req = service_request(GetFlowRequest {
            id: "settings-flow".to_string(),
            ..Default::default()
        });
        let resp = svc.get_settings_flow(ctx.clone(), get_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "get_settings_flow(id=settings-flow, cookie=None)");

        fake.reseed_flow(sample_flow());
        let submit_req = service_request(SubmitFlowRequest {
            id: "settings-flow".to_string(),
            ..Default::default()
        });
        let resp = svc.submit_settings_flow(ctx.clone(), submit_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "submit_settings_flow(id=settings-flow, cookie=None, body=");

        fake.reseed_flow(sample_flow());
        let create_req = service_request(CreateSettingsFlowRequest {
            return_to: "http://return".to_string(),
            ..Default::default()
        });
        let resp = svc.create_settings_flow(ctx, create_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "create_settings_browser_flow(return_to=Some(\"http://return\"), cookie=None)");
    }

    #[tokio::test]
    async fn recovery_flow_methods_cover_happy_and_error() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_tenant("tenant-1");

        let get_req = service_request(GetFlowRequest {
            id: "recovery-flow".to_string(),
            ..Default::default()
        });
        let resp = svc.get_recovery_flow(ctx.clone(), get_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "get_recovery_flow(id=recovery-flow, cookie=None)");

        fake.reseed_flow(sample_flow());
        let submit_req = service_request(SubmitFlowRequest {
            id: "recovery-flow".to_string(),
            ..Default::default()
        });
        let resp = svc.submit_recovery_flow(ctx.clone(), submit_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "submit_recovery_flow(id=recovery-flow, cookie=None, body=");

        fake.reseed_flow(sample_flow());
        let create_req = service_request(CreateRecoveryFlowRequest {
            return_to: "http://return".to_string(),
            ..Default::default()
        });
        let resp = svc.create_recovery_flow(ctx, create_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "create_recovery_browser_flow(return_to=Some(\"http://return\"), cookie=None)");
    }

    #[tokio::test]
    async fn verification_flow_methods_cover_happy_and_error() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_tenant("tenant-1");

        let get_req = service_request(GetFlowRequest {
            id: "verification-flow".to_string(),
            ..Default::default()
        });
        let resp = svc.get_verification_flow(ctx.clone(), get_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "get_verification_flow(id=verification-flow, cookie=None)");

        fake.reseed_flow(sample_flow());
        let submit_req = service_request(SubmitFlowRequest {
            id: "verification-flow".to_string(),
            ..Default::default()
        });
        let resp = svc
            .submit_verification_flow(ctx.clone(), submit_req)
            .await
            .unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "submit_verification_flow(id=verification-flow, cookie=None, body=");

        fake.reseed_flow(sample_flow());
        let create_req = service_request(CreateVerificationFlowRequest {
            return_to: "http://return".to_string(),
            ..Default::default()
        });
        let resp = svc.create_verification_flow(ctx, create_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(fake, "create_verification_flow(return_to=Some(\"http://return\"), cookie=None)");
    }

    #[tokio::test]
    async fn registration_flow_methods_error_branch() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 403,
                message: "forbidden".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_tenant("tenant-1");

        let get_req = service_request(GetFlowRequest {
            id: "registration-flow".to_string(),
            ..Default::default()
        });
        assert_eq!(
            svc.get_registration_flow(ctx.clone(), get_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );

        fake.reseed_flow_error(403, "forbidden");
        let submit_req = service_request(SubmitFlowRequest {
            id: "registration-flow".to_string(),
            ..Default::default()
        });
        assert_eq!(
            svc.submit_registration_flow(ctx.clone(), submit_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );

        fake.reseed_flow_error(403, "forbidden");
        let create_req = service_request(CreateRegistrationFlowRequest::default());
        assert_eq!(
            svc.create_registration_flow(ctx, create_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );
    }

    #[tokio::test]
    async fn settings_flow_methods_error_branch() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 403,
                message: "forbidden".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_tenant("tenant-1");

        let get_req = service_request(GetFlowRequest {
            id: "settings-flow".to_string(),
            ..Default::default()
        });
        assert_eq!(
            svc.get_settings_flow(ctx.clone(), get_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );

        fake.reseed_flow_error(403, "forbidden");
        let submit_req = service_request(SubmitFlowRequest {
            id: "settings-flow".to_string(),
            ..Default::default()
        });
        assert_eq!(
            svc.submit_settings_flow(ctx.clone(), submit_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );

        fake.reseed_flow_error(403, "forbidden");
        let create_req = service_request(CreateSettingsFlowRequest::default());
        assert_eq!(
            svc.create_settings_flow(ctx, create_req).await.unwrap_err().code,
            ErrorCode::PermissionDenied
        );
    }

    #[tokio::test]
    async fn recovery_flow_methods_error_branch() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 403,
                message: "forbidden".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_tenant("tenant-1");

        let get_req = service_request(GetFlowRequest {
            id: "recovery-flow".to_string(),
            ..Default::default()
        });
        assert_eq!(
            svc.get_recovery_flow(ctx.clone(), get_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );

        fake.reseed_flow_error(403, "forbidden");
        let submit_req = service_request(SubmitFlowRequest {
            id: "recovery-flow".to_string(),
            ..Default::default()
        });
        assert_eq!(
            svc.submit_recovery_flow(ctx.clone(), submit_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );

        fake.reseed_flow_error(403, "forbidden");
        let create_req = service_request(CreateRecoveryFlowRequest::default());
        assert_eq!(
            svc.create_recovery_flow(ctx, create_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );
    }

    #[tokio::test]
    async fn verification_flow_methods_error_branch() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 403,
                message: "forbidden".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_tenant("tenant-1");

        let get_req = service_request(GetFlowRequest {
            id: "verification-flow".to_string(),
            ..Default::default()
        });
        assert_eq!(
            svc.get_verification_flow(ctx.clone(), get_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );

        fake.reseed_flow_error(403, "forbidden");
        let submit_req = service_request(SubmitFlowRequest {
            id: "verification-flow".to_string(),
            ..Default::default()
        });
        assert_eq!(
            svc.submit_verification_flow(ctx.clone(), submit_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );

        fake.reseed_flow_error(403, "forbidden");
        let create_req = service_request(CreateVerificationFlowRequest::default());
        assert_eq!(
            svc.create_verification_flow(ctx, create_req)
                .await
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );
    }
}
