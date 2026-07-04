use std::sync::Arc;

use async_trait::async_trait;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::{
    error::OryClientError,
    kratos::{KratosClient, KratosResponse},
};
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;

use crate::middleware::TenantId;
use crate::proto::iam::v1::{
    BrowserSession, CreateLoginFlowRequest, CreateLogoutFlowRequest, CreateRecoveryFlowRequest,
    CreateRegistrationFlowRequest, CreateSettingsFlowRequest, CreateVerificationFlowRequest,
    FlowError, GetFlowErrorRequest, GetFlowRequest, GetTenantCapabilitiesRequest,
    GetTenantCapabilitiesResponse, IdentitySelfService, LogoutFlow, SelfServiceFlow,
    SubmitFlowRequest, SubmitLogoutFlowRequest, SubmitRecoveryTokenRequest,
    SubmitRecoveryTokenResponse, SubmitVerificationTokenRequest, SubmitVerificationTokenResponse,
    TenantCapabilities, ToSessionRequest, WebAuthnJsResponse,
};
use buffa_types::google::protobuf::Empty;

use super::identity_self_service_mapper::{
    ory_flow_error_to_proto, ory_flow_to_proto, ory_logout_flow_to_proto, ory_session_to_proto,
    ory_webauthn_js_to_proto, proto_struct_to_json,
};
use super::self_service_url_rewriter::rewrite_url;

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

    async fn get_login_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn get_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn get_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn get_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn get_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn submit_login_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError>;

    async fn submit_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError>;

    async fn submit_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError>;

    async fn submit_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError>;

    async fn submit_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError>;

    async fn create_login_browser_flow(
        &self,
        query: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn create_registration_browser_flow(
        &self,
        query: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn create_settings_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn create_recovery_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn create_verification_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn create_logout_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn submit_logout_flow(
        &self,
        token: &str,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<(), OryClientError>;

    async fn get_flow_error(&self, id: &str) -> Result<Value, OryClientError>;

    async fn get_webauthn_js(&self) -> Result<String, OryClientError>;

    async fn submit_recovery_token(
        &self,
        token: &str,
        cookie: Option<&str>,
        csrf_token: Option<&str>,
    ) -> Result<sso_ory_client::kratos::KratosRedirectResponse, OryClientError>;

    async fn submit_verification_token(
        &self,
        token: &str,
        cookie: Option<&str>,
        csrf_token: Option<&str>,
    ) -> Result<sso_ory_client::kratos::KratosRedirectResponse, OryClientError>;
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

    async fn get_login_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.get_login_flow(id, cookie).await
    }

    async fn get_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.get_registration_flow(id, cookie).await
    }

    async fn get_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.get_settings_flow(id, cookie).await
    }

    async fn get_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.get_recovery_flow(id, cookie).await
    }

    async fn get_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.get_verification_flow(id, cookie).await
    }

    async fn submit_login_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        self.submit_login_flow(id, cookie, body).await
    }

    async fn submit_registration_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        self.submit_registration_flow(id, cookie, body).await
    }

    async fn submit_settings_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        self.submit_settings_flow(id, cookie, body).await
    }

    async fn submit_recovery_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        self.submit_recovery_flow(id, cookie, body).await
    }

    async fn submit_verification_flow(
        &self,
        id: &str,
        cookie: Option<&str>,
        body: Value,
    ) -> Result<KratosResponse, OryClientError> {
        self.submit_verification_flow(id, cookie, body).await
    }

    async fn create_login_browser_flow(
        &self,
        query: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.create_login_browser_flow(query, cookie).await
    }

    async fn create_registration_browser_flow(
        &self,
        query: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.create_registration_browser_flow(query, cookie).await
    }

    async fn create_settings_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.create_settings_browser_flow(return_to, cookie).await
    }

    async fn create_recovery_browser_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.create_recovery_browser_flow(return_to, cookie).await
    }

    async fn create_verification_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
        self.create_verification_flow(return_to, cookie).await
    }

    async fn create_logout_flow(
        &self,
        return_to: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<KratosResponse, OryClientError> {
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

    async fn submit_recovery_token(
        &self,
        token: &str,
        cookie: Option<&str>,
        csrf_token: Option<&str>,
    ) -> Result<sso_ory_client::kratos::KratosRedirectResponse, OryClientError> {
        self.submit_recovery_token(token, cookie, csrf_token).await
    }

    async fn submit_verification_token(
        &self,
        token: &str,
        cookie: Option<&str>,
        csrf_token: Option<&str>,
    ) -> Result<sso_ory_client::kratos::KratosRedirectResponse, OryClientError> {
        self.submit_verification_token(token, cookie, csrf_token)
            .await
    }
}

#[derive(Clone)]
pub struct IdentitySelfServiceImpl {
    kratos: Arc<dyn KratosSelfService>,
    consent_enabled: bool,
    kratos_public_url: String,
    gateway_public_url: String,
}

impl IdentitySelfServiceImpl {
    pub fn new(
        kratos: Arc<KratosClient>,
        consent_enabled: bool,
        kratos_public_url: String,
        gateway_public_url: String,
    ) -> Self {
        Self {
            kratos: kratos as Arc<dyn KratosSelfService>,
            consent_enabled,
            kratos_public_url,
            gateway_public_url,
        }
    }

    fn rewrite_flow_urls(&self, flow: &mut SelfServiceFlow) {
        flow.return_to = rewrite_url(
            &flow.return_to,
            &self.kratos_public_url,
            &self.gateway_public_url,
        );
        flow.request_url = rewrite_url(
            &flow.request_url,
            &self.kratos_public_url,
            &self.gateway_public_url,
        );
        if let Some(ui) = flow.ui.as_option_mut() {
            ui.action = rewrite_url(
                &ui.action,
                &self.kratos_public_url,
                &self.gateway_public_url,
            );
            for node in &mut ui.nodes {
                if let Some(crate::proto::iam::v1::ui_node::Attributes::Anchor(attrs)) =
                    node.attributes.as_mut()
                {
                    attrs.href = rewrite_url(
                        &attrs.href,
                        &self.kratos_public_url,
                        &self.gateway_public_url,
                    );
                }
                if let Some(crate::proto::iam::v1::ui_node::Attributes::Image(attrs)) =
                    node.attributes.as_mut()
                {
                    attrs.src = rewrite_url(
                        &attrs.src,
                        &self.kratos_public_url,
                        &self.gateway_public_url,
                    );
                }
                if let Some(crate::proto::iam::v1::ui_node::Attributes::Script(attrs)) =
                    node.attributes.as_mut()
                {
                    attrs.src = rewrite_url(
                        &attrs.src,
                        &self.kratos_public_url,
                        &self.gateway_public_url,
                    );
                }
                if let Some(crate::proto::iam::v1::ui_node::Attributes::Input(attrs)) =
                    node.attributes.as_mut()
                {
                    attrs.src = rewrite_url(
                        &attrs.src,
                        &self.kratos_public_url,
                        &self.gateway_public_url,
                    );
                }
            }
        }
        if let Some(oauth2) = flow.oauth2_login_request.as_option_mut()
            && let Some(client) = oauth2.client.as_option_mut()
        {
            for uri in &mut client.redirect_uris {
                *uri = rewrite_url(uri, &self.kratos_public_url, &self.gateway_public_url);
            }
            client.client_uri = rewrite_url(
                &client.client_uri,
                &self.kratos_public_url,
                &self.gateway_public_url,
            );
            client.logo_uri = rewrite_url(
                &client.logo_uri,
                &self.kratos_public_url,
                &self.gateway_public_url,
            );
            client.policy_uri = rewrite_url(
                &client.policy_uri,
                &self.kratos_public_url,
                &self.gateway_public_url,
            );
            client.tos_uri = rewrite_url(
                &client.tos_uri,
                &self.kratos_public_url,
                &self.gateway_public_url,
            );
            client.jwks_uri = rewrite_url(
                &client.jwks_uri,
                &self.kratos_public_url,
                &self.gateway_public_url,
            );
        }
    }
}

fn cookie_from_context(ctx: &RequestContext) -> Option<String> {
    ctx.headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

fn csrf_token_from_context(ctx: &RequestContext) -> Option<String> {
    ctx.headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

fn tenant_from_context(ctx: &RequestContext) -> String {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .unwrap_or_default()
}

fn attach_set_cookies<T>(response: &mut Response<T>, headers: &http::HeaderMap) {
    for cookie in headers.get_all("set-cookie") {
        response.headers.append("set-cookie", cookie.clone());
    }
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
    }

    #[instrument(skip(self, request))]
    async fn create_login_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateLoginFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let mut query = Vec::<(&str, &str)>::new();
        if !req.return_to.is_empty() {
            query.push(("return_to", req.return_to.as_str()));
        }
        if !req.aal.is_empty() {
            query.push(("aal", req.aal.as_str()));
        }
        if req.refresh {
            query.push(("refresh", "true"));
        }
        if !req.organization.is_empty() {
            query.push(("organization", req.organization.as_str()));
        }
        if !req.via.is_empty() {
            query.push(("via", req.via.as_str()));
        }
        if !req.login_challenge.is_empty() {
            query.push(("login_challenge", req.login_challenge.as_str()));
        }
        if !req.identity_schema.is_empty() {
            query.push(("identity_schema", req.identity_schema.as_str()));
        }
        let flow = self
            .kratos
            .create_login_browser_flow(&query, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
    }

    #[instrument(skip(self, request))]
    async fn create_registration_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateRegistrationFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let mut query = Vec::<(&str, &str)>::new();
        if !req.return_to.is_empty() {
            query.push(("return_to", req.return_to.as_str()));
        }
        if !req.login_challenge.is_empty() {
            query.push(("login_challenge", req.login_challenge.as_str()));
        }
        if !req.identity_schema.is_empty() {
            query.push(("identity_schema", req.identity_schema.as_str()));
        }
        let flow = self
            .kratos
            .create_registration_browser_flow(&query, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_logout_flow_to_proto(&flow.body));
        response.body.logout_url = rewrite_url(
            &response.body.logout_url,
            &self.kratos_public_url,
            &self.gateway_public_url,
        );
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
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
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.rewrite_flow_urls(&mut response.body);
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
    }

    #[instrument(skip(self, request))]
    async fn submit_recovery_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitRecoveryTokenRequest>,
    ) -> ServiceResult<SubmitRecoveryTokenResponse> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let csrf_token = csrf_token_from_context(&ctx);
        let redirect = self
            .kratos
            .submit_recovery_token(&req.token, cookie.as_deref(), csrf_token.as_deref())
            .await
            .map_err(map_ory_error)?;
        let redirect_to = redirect.location.ok_or_else(|| {
            ServiceError::Internal("kratos recovery token response missing location".into())
        })?;
        let mut response = Response::new(SubmitRecoveryTokenResponse {
            redirect_to,
            __buffa_unknown_fields: Default::default(),
        });
        attach_set_cookies(&mut response, &redirect.headers);
        Ok(response)
    }

    #[instrument(skip(self, request))]
    async fn submit_verification_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitVerificationTokenRequest>,
    ) -> ServiceResult<SubmitVerificationTokenResponse> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let csrf_token = csrf_token_from_context(&ctx);
        let redirect = self
            .kratos
            .submit_verification_token(&req.token, cookie.as_deref(), csrf_token.as_deref())
            .await
            .map_err(map_ory_error)?;
        let redirect_to = redirect.location.ok_or_else(|| {
            ServiceError::Internal("kratos verification token response missing location".into())
        })?;
        let mut response = Response::new(SubmitVerificationTokenResponse {
            redirect_to,
            __buffa_unknown_fields: Default::default(),
        });
        attach_set_cookies(&mut response, &redirect.headers);
        Ok(response)
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

    #[instrument(skip(self))]
    async fn get_tenant_capabilities(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetTenantCapabilitiesRequest>,
    ) -> ServiceResult<GetTenantCapabilitiesResponse> {
        Ok(Response::new(GetTenantCapabilitiesResponse {
            capabilities: Some(TenantCapabilities {
                oauth2_consent_enabled: self.consent_enabled,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }))
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

    use buffa::{HasMessageView, Message, MessageView, bytes::Bytes};
    use connectrpc::{ErrorCode, RequestContext, ServiceRequest};
    use http::HeaderMap;
    use serde_json::{Value, json};
    use sso_ory_client::{
        error::OryClientError,
        kratos::{KratosClient, KratosRedirectResponse, KratosResponse},
    };
    use sunbeam_g2v::error::ServiceError;

    use crate::middleware::TenantId;
    use crate::proto::iam::v1::{
        CreateLoginFlowRequest, CreateLogoutFlowRequest, CreateRecoveryFlowRequest,
        CreateRegistrationFlowRequest, CreateSettingsFlowRequest, CreateVerificationFlowRequest,
        GetFlowErrorRequest, GetFlowRequest, GetTenantCapabilitiesRequest, IdentitySelfService,
        SelfServiceFlow, SubmitFlowRequest, SubmitLogoutFlowRequest, SubmitRecoveryTokenRequest,
        SubmitVerificationTokenRequest, ToSessionRequest,
    };

    use super::{
        IdentitySelfServiceImpl, KratosSelfService, cookie_from_context, csrf_token_from_context,
        map_ory_error, tenant_from_context,
    };

    fn request_context_with_cookie(cookie: &str) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie.parse().unwrap());
        RequestContext::new(headers)
    }

    fn request_context_with_cookie_and_csrf(cookie: &str, csrf: &str) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie.parse().unwrap());
        headers.insert("x-csrf-token", csrf.parse().unwrap());
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

    fn sample_flow() -> KratosResponse {
        KratosResponse {
            body: json!({
                "id": "flow-1",
                "type": "login",
                "state": "choose_method"
            }),
            headers: http::HeaderMap::new(),
        }
    }

    fn sample_session() -> Value {
        json!({
            "id": "session-1",
            "active": true,
            "identity": { "id": "identity-1" }
        })
    }

    fn sample_logout_flow() -> KratosResponse {
        KratosResponse {
            body: json!({
                "id": "logout-1",
                "logout_url": "http://logout",
                "logout_token": "token-1"
            }),
            headers: http::HeaderMap::new(),
        }
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
        flow: Arc<Mutex<Option<Result<KratosResponse, OryClientError>>>>,
        logout_flow: Arc<Mutex<Option<Result<KratosResponse, OryClientError>>>>,
        logout_submit: Arc<Mutex<Option<Result<(), OryClientError>>>>,
        flow_error: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        webauthn_js: Arc<Mutex<Option<Result<String, OryClientError>>>>,
        token_submit: Arc<Mutex<Option<Result<KratosRedirectResponse, OryClientError>>>>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl FakeKratos {
        fn take_flow(&self) -> Result<KratosResponse, OryClientError> {
            self.flow
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        fn reseed_flow(&self, value: KratosResponse) {
            *self.flow.lock().unwrap() = Some(Ok(value));
        }

        fn reseed_flow_with_cookies(&self, value: Value, cookies: &[&str]) {
            let mut headers = http::HeaderMap::new();
            for cookie in cookies {
                headers.append("set-cookie", cookie.parse().unwrap());
            }
            *self.flow.lock().unwrap() = Some(Ok(KratosResponse {
                body: value,
                headers,
            }));
        }

        fn reseed_flow_error(&self, status: u16, message: &str) {
            *self.flow.lock().unwrap() = Some(Err(OryClientError::Ory {
                status,
                message: message.to_string(),
            }));
        }

        fn take_token_submit(&self) -> Result<KratosRedirectResponse, OryClientError> {
            self.token_submit
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        fn reseed_token_submit(&self, location: &str, cookies: &[&str]) {
            let mut headers = http::HeaderMap::new();
            for cookie in cookies {
                headers.append("set-cookie", cookie.parse().unwrap());
            }
            *self.token_submit.lock().unwrap() = Some(Ok(KratosRedirectResponse {
                location: Some(location.to_string()),
                headers,
            }));
        }

        fn reseed_token_submit_without_location(&self) {
            *self.token_submit.lock().unwrap() = Some(Ok(KratosRedirectResponse {
                location: None,
                headers: http::HeaderMap::new(),
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
        ) -> Result<KratosResponse, OryClientError> {
            self.record(format!("get_login_flow(id={id}, cookie={:?})", cookie));
            self.take_flow()
        }

        async fn get_registration_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
        ) -> Result<KratosResponse, OryClientError> {
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
        ) -> Result<KratosResponse, OryClientError> {
            self.record(format!("get_settings_flow(id={id}, cookie={:?})", cookie));
            self.take_flow()
        }

        async fn get_recovery_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
        ) -> Result<KratosResponse, OryClientError> {
            self.record(format!("get_recovery_flow(id={id}, cookie={:?})", cookie));
            self.take_flow()
        }

        async fn get_verification_flow(
            &self,
            id: &str,
            cookie: Option<&str>,
        ) -> Result<KratosResponse, OryClientError> {
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
        ) -> Result<KratosResponse, OryClientError> {
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
        ) -> Result<KratosResponse, OryClientError> {
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
        ) -> Result<KratosResponse, OryClientError> {
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
        ) -> Result<KratosResponse, OryClientError> {
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
        ) -> Result<KratosResponse, OryClientError> {
            self.record(format!(
                "submit_verification_flow(id={id}, cookie={:?}, body={body})",
                cookie
            ));
            self.take_flow()
        }

        async fn create_login_browser_flow(
            &self,
            query: &[(&str, &str)],
            cookie: Option<&str>,
        ) -> Result<KratosResponse, OryClientError> {
            self.record(format!(
                "create_login_browser_flow(query={:?}, cookie={:?})",
                query, cookie
            ));
            self.take_flow()
        }

        async fn create_registration_browser_flow(
            &self,
            query: &[(&str, &str)],
            cookie: Option<&str>,
        ) -> Result<KratosResponse, OryClientError> {
            self.record(format!(
                "create_registration_browser_flow(query={:?}, cookie={:?})",
                query, cookie
            ));
            self.take_flow()
        }

        async fn create_settings_browser_flow(
            &self,
            return_to: Option<&str>,
            cookie: Option<&str>,
        ) -> Result<KratosResponse, OryClientError> {
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
        ) -> Result<KratosResponse, OryClientError> {
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
        ) -> Result<KratosResponse, OryClientError> {
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
        ) -> Result<KratosResponse, OryClientError> {
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

        async fn submit_recovery_token(
            &self,
            token: &str,
            cookie: Option<&str>,
            csrf_token: Option<&str>,
        ) -> Result<KratosRedirectResponse, OryClientError> {
            self.record(format!(
                "submit_recovery_token(token={token}, cookie={:?}, csrf_token={:?})",
                cookie, csrf_token
            ));
            self.take_token_submit()
        }

        async fn submit_verification_token(
            &self,
            token: &str,
            cookie: Option<&str>,
            csrf_token: Option<&str>,
        ) -> Result<KratosRedirectResponse, OryClientError> {
            self.record(format!(
                "submit_verification_token(token={token}, cookie={:?}, csrf_token={:?})",
                cookie, csrf_token
            ));
            self.take_token_submit()
        }
    }

    fn service(kratos: FakeKratos) -> IdentitySelfServiceImpl {
        IdentitySelfServiceImpl {
            kratos: Arc::new(kratos),
            consent_enabled: true,
            kratos_public_url: "http://kratos.example.com".to_string(),
            gateway_public_url: "https://gateway.example.com".to_string(),
        }
    }

    #[test]
    fn new_stores_kratos_client() {
        let kratos = Arc::new(KratosClient::new("http://localhost:4434").unwrap());
        let svc = IdentitySelfServiceImpl::new(
            kratos.clone(),
            true,
            "http://kratos.example.com".to_string(),
            "https://gateway.example.com".to_string(),
        );
        // Field is now a trait object; just verify the service was created.
        assert_eq!(Arc::strong_count(&kratos), 2);
        let _ = svc;
    }

    #[tokio::test]
    async fn get_tenant_capabilities_returns_consent_flag() {
        let svc = service(FakeKratos::default());
        let req = GetTenantCapabilitiesRequest::default();
        let svc_req = service_request(req);
        let resp = IdentitySelfService::get_tenant_capabilities(
            &svc,
            request_context_without_cookie(),
            svc_req,
        )
        .await
        .unwrap()
        .body;
        let caps = resp.capabilities.as_option().unwrap();
        assert!(caps.oauth2_consent_enabled);
    }

    #[test]
    fn rewrite_flow_urls_rewrites_ui_action() {
        let svc = service(FakeKratos::default());
        let mut flow = SelfServiceFlow {
            ui: Some(crate::proto::iam::v1::UiContainer {
                action: "http://kratos.example.com/self-service/login?flow=1".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        svc.rewrite_flow_urls(&mut flow);
        assert_eq!(
            flow.ui.as_option().unwrap().action,
            "https://gateway.example.com/self-service/login?flow=1"
        );
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
        ctx.extensions_mut()
            .insert(TenantId("tenant-1".to_string()));
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
        assert!(fake.calls.lock().unwrap()[0].starts_with(
            "create_login_browser_flow(query=[(\"return_to\", \"http://return\")], cookie=Some("
        ));
    }

    #[tokio::test]
    async fn create_login_flow_forwards_all_query_params() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(CreateLoginFlowRequest {
            return_to: "http://return".to_string(),
            aal: "aal2".to_string(),
            refresh: true,
            organization: "org-1".to_string(),
            via: "email".to_string(),
            login_challenge: "challenge-1".to_string(),
            identity_schema: "default".to_string(),
            ..Default::default()
        });

        svc.create_login_flow(ctx, req).await.unwrap();
        let call = &fake.calls.lock().unwrap()[0];
        assert!(call.starts_with("create_login_browser_flow(query=["));
        assert!(call.contains("(\"return_to\", \"http://return\")"));
        assert!(call.contains("(\"aal\", \"aal2\")"));
        assert!(call.contains("(\"refresh\", \"true\")"));
        assert!(call.contains("(\"organization\", \"org-1\")"));
        assert!(call.contains("(\"via\", \"email\")"));
        assert!(call.contains("(\"login_challenge\", \"challenge-1\")"));
        assert!(call.contains("(\"identity_schema\", \"default\")"));
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
        assert!(fake.calls.lock().unwrap()[0].starts_with(
            "submit_logout_flow(token=token-1, return_to=Some(\"http://return\"), cookie=Some("
        ));
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

    #[tokio::test]
    async fn submit_recovery_token_happy_path() {
        let fake = FakeKratos::default();
        fake.reseed_token_submit(
            "https://ui.example.com/settings?flow=privileged",
            &[
                "ory_kratos_session=abc; Path=/; HttpOnly",
                "csrf_token_1234=xyz; Path=/; SameSite=Lax",
            ],
        );
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie_and_csrf("session=prev", "csrf-header-value");
        let req = service_request(SubmitRecoveryTokenRequest {
            token: "recovery-token-1".to_string(),
            ..Default::default()
        });

        let resp = svc.submit_recovery_token(ctx, req).await.unwrap();
        assert_eq!(
            resp.body.redirect_to,
            "https://ui.example.com/settings?flow=privileged"
        );
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2);
        assert_eq!(
            fake.calls.lock().unwrap()[0],
            "submit_recovery_token(token=recovery-token-1, cookie=Some(\"session=prev\"), csrf_token=Some(\"csrf-header-value\"))"
        );
    }

    #[tokio::test]
    async fn submit_recovery_token_missing_location_returns_internal() {
        let fake = FakeKratos::default();
        fake.reseed_token_submit_without_location();
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(SubmitRecoveryTokenRequest {
            token: "token".to_string(),
            ..Default::default()
        });

        let err = svc.submit_recovery_token(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
    }

    #[tokio::test]
    async fn submit_recovery_token_error_path() {
        let fake = FakeKratos {
            token_submit: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 410,
                message: "token expired".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(SubmitRecoveryTokenRequest {
            token: "expired".to_string(),
            ..Default::default()
        });

        let err = svc.submit_recovery_token(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
    }

    #[tokio::test]
    async fn submit_verification_token_happy_path() {
        let fake = FakeKratos::default();
        fake.reseed_token_submit(
            "https://ui.example.com/welcome?verified=true",
            &["ory_kratos_session=abc; Path=/; HttpOnly"],
        );
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie_and_csrf("session=prev", "csrf-header-value");
        let req = service_request(SubmitVerificationTokenRequest {
            token: "verification-token-1".to_string(),
            ..Default::default()
        });

        let resp = svc.submit_verification_token(ctx, req).await.unwrap();
        assert_eq!(
            resp.body.redirect_to,
            "https://ui.example.com/welcome?verified=true"
        );
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            fake.calls.lock().unwrap()[0],
            "submit_verification_token(token=verification-token-1, cookie=Some(\"session=prev\"), csrf_token=Some(\"csrf-header-value\"))"
        );
    }

    #[tokio::test]
    async fn submit_verification_token_missing_location_returns_internal() {
        let fake = FakeKratos::default();
        fake.reseed_token_submit_without_location();
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(SubmitVerificationTokenRequest {
            token: "token".to_string(),
            ..Default::default()
        });

        let err = svc.submit_verification_token(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
    }

    #[tokio::test]
    async fn submit_verification_token_error_path() {
        let fake = FakeKratos {
            token_submit: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 404,
                message: "token not found".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(SubmitVerificationTokenRequest {
            token: "missing".to_string(),
            ..Default::default()
        });

        let err = svc.submit_verification_token(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[test]
    fn csrf_token_from_context_extracts_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-csrf-token", "token-value".parse().unwrap());
        let ctx = RequestContext::new(headers);
        assert_eq!(
            csrf_token_from_context(&ctx),
            Some("token-value".to_string())
        );
    }

    #[test]
    fn csrf_token_from_context_returns_none_when_missing() {
        let ctx = RequestContext::new(HeaderMap::new());
        assert_eq!(csrf_token_from_context(&ctx), None);
    }

    macro_rules! assert_flow_call {
        ($fake:expr, $prefix:literal) => {
            assert!(
                $fake
                    .calls
                    .lock()
                    .unwrap()
                    .last()
                    .unwrap()
                    .starts_with($prefix),
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
        let resp = svc
            .get_registration_flow(ctx.clone(), get_req)
            .await
            .unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(
            fake,
            "get_registration_flow(id=registration-flow, cookie=None)"
        );

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
        assert_flow_call!(
            fake,
            "submit_registration_flow(id=registration-flow, cookie=None, body="
        );

        fake.reseed_flow(sample_flow());
        let create_req = service_request(CreateRegistrationFlowRequest {
            return_to: "http://return".to_string(),
            ..Default::default()
        });
        let resp = svc.create_registration_flow(ctx, create_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(
            fake,
            "create_registration_browser_flow(query=[(\"return_to\", \"http://return\")], cookie=None)"
        );
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
        let resp = svc
            .submit_settings_flow(ctx.clone(), submit_req)
            .await
            .unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(
            fake,
            "submit_settings_flow(id=settings-flow, cookie=None, body="
        );

        fake.reseed_flow(sample_flow());
        let create_req = service_request(CreateSettingsFlowRequest {
            return_to: "http://return".to_string(),
            ..Default::default()
        });
        let resp = svc.create_settings_flow(ctx, create_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(
            fake,
            "create_settings_browser_flow(return_to=Some(\"http://return\"), cookie=None)"
        );
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
        let resp = svc
            .submit_recovery_flow(ctx.clone(), submit_req)
            .await
            .unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(
            fake,
            "submit_recovery_flow(id=recovery-flow, cookie=None, body="
        );

        fake.reseed_flow(sample_flow());
        let create_req = service_request(CreateRecoveryFlowRequest {
            return_to: "http://return".to_string(),
            ..Default::default()
        });
        let resp = svc.create_recovery_flow(ctx, create_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(
            fake,
            "create_recovery_browser_flow(return_to=Some(\"http://return\"), cookie=None)"
        );
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
        let resp = svc
            .get_verification_flow(ctx.clone(), get_req)
            .await
            .unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(
            fake,
            "get_verification_flow(id=verification-flow, cookie=None)"
        );

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
        assert_flow_call!(
            fake,
            "submit_verification_flow(id=verification-flow, cookie=None, body="
        );

        fake.reseed_flow(sample_flow());
        let create_req = service_request(CreateVerificationFlowRequest {
            return_to: "http://return".to_string(),
            ..Default::default()
        });
        let resp = svc.create_verification_flow(ctx, create_req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert_flow_call!(
            fake,
            "create_verification_flow(return_to=Some(\"http://return\"), cookie=None)"
        );
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
            svc.create_settings_flow(ctx, create_req)
                .await
                .unwrap_err()
                .code,
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

    #[tokio::test]
    async fn create_login_flow_propagates_set_cookie_headers() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(KratosResponse {
                body: sample_flow().body,
                headers: {
                    let mut h = http::HeaderMap::new();
                    h.append(
                        "set-cookie",
                        "ory_kratos_session=a; Path=/; HttpOnly".parse().unwrap(),
                    );
                    h.append(
                        "set-cookie",
                        "ory_kratos_continuity=b; Path=/; HttpOnly".parse().unwrap(),
                    );
                    h
                },
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(CreateLoginFlowRequest::default());

        let resp = svc.create_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2);
    }

    #[tokio::test]
    async fn get_login_flow_propagates_set_cookie_headers() {
        let fake = FakeKratos::default();
        fake.reseed_flow_with_cookies(
            json!({ "id": "flow-1", "type": "login", "state": "choose_method" }),
            &["ory_kratos_session=a; Path=/; HttpOnly"],
        );
        let svc = service(fake);
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(GetFlowRequest {
            id: "flow-1".to_string(),
            ..Default::default()
        });

        let resp = svc.get_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
    }

    #[tokio::test]
    async fn submit_login_flow_propagates_set_cookie_headers() {
        let fake = FakeKratos::default();
        fake.reseed_flow_with_cookies(
            json!({ "id": "flow-1", "type": "login", "state": "passed_challenge" }),
            &["ory_kratos_session=a; Path=/; HttpOnly"],
        );
        let svc = service(fake);
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(SubmitFlowRequest {
            id: "flow-1".to_string(),
            ..Default::default()
        });

        let resp = svc.submit_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
    }

    #[tokio::test]
    async fn create_logout_flow_propagates_set_cookie_headers() {
        let fake = FakeKratos {
            logout_flow: Arc::new(Mutex::new(Some(Ok(KratosResponse {
                body: json!({ "id": "logout-1", "logout_token": "token-1" }),
                headers: {
                    let mut h = http::HeaderMap::new();
                    h.append(
                        "set-cookie",
                        "ory_kratos_session=; Path=/; Max-Age=0".parse().unwrap(),
                    );
                    h
                },
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(CreateLogoutFlowRequest::default());

        let resp = svc.create_logout_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.logout_token, "token-1");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
    }

    #[tokio::test]
    async fn kratos_client_as_self_service_trait_delegates() {
        let client = Arc::new(
            KratosClient::new_with_public("http://localhost:1", "http://localhost:1").unwrap(),
        ) as Arc<dyn KratosSelfService>;
        assert!(client.to_session(None, None).await.is_err());
        assert!(client.get_login_flow("id", None).await.is_err());
        assert!(client.get_registration_flow("id", None).await.is_err());
        assert!(client.get_settings_flow("id", None).await.is_err());
        assert!(client.get_recovery_flow("id", None).await.is_err());
        assert!(client.get_verification_flow("id", None).await.is_err());
        assert!(
            client
                .submit_login_flow("id", None, json!({}))
                .await
                .is_err()
        );
        assert!(
            client
                .submit_registration_flow("id", None, json!({}))
                .await
                .is_err()
        );
        assert!(
            client
                .submit_settings_flow("id", None, json!({}))
                .await
                .is_err()
        );
        assert!(
            client
                .submit_recovery_flow("id", None, json!({}))
                .await
                .is_err()
        );
        assert!(
            client
                .submit_verification_flow("id", None, json!({}))
                .await
                .is_err()
        );
        assert!(
            client
                .submit_recovery_token("token", None, None)
                .await
                .is_err()
        );
        assert!(
            client
                .submit_verification_token("token", None, None)
                .await
                .is_err()
        );
        assert!(client.create_login_browser_flow(&[], None).await.is_err());
        assert!(
            client
                .create_registration_browser_flow(&[], None)
                .await
                .is_err()
        );
        assert!(
            client
                .create_settings_browser_flow(None, None)
                .await
                .is_err()
        );
        assert!(
            client
                .create_recovery_browser_flow(None, None)
                .await
                .is_err()
        );
        assert!(client.create_verification_flow(None, None).await.is_err());
        assert!(client.create_logout_flow(None, None).await.is_err());
        assert!(
            client
                .submit_logout_flow("token", None, None)
                .await
                .is_err()
        );
        assert!(client.get_flow_error("id").await.is_err());
        assert!(client.get_webauthn_js().await.is_err());
    }
}
