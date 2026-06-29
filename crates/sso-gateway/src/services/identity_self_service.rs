use std::sync::Arc;

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
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

#[derive(Clone)]
pub struct IdentitySelfServiceImpl {
    kratos: Arc<KratosClient>,
}

impl IdentitySelfServiceImpl {
    pub fn new(kratos: Arc<KratosClient>) -> Self {
        Self { kratos }
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
    use sso_ory_client::error::OryClientError;
    use sunbeam_g2v::error::ServiceError;

    use super::map_ory_error;

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
}
