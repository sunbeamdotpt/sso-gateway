use std::sync::Arc;

use async_trait::async_trait;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::{
    error::OryClientError,
    hydra::HydraClient,
    kratos::{KratosClient, KratosResponse},
};
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;

use crate::db::{
    DbError, IdMappingRepo, IdMappingStore, IdentitySchemaRepo, IdentitySchemaStore,
    TOKEN_TYPE_FLOW, TOKEN_TYPE_LOGIN_CHALLENGE, TOKEN_TYPE_LOGOUT_TOKEN,
    TOKEN_TYPE_RECOVERY_TOKEN, TOKEN_TYPE_SESSION, TOKEN_TYPE_VERIFICATION_TOKEN,
    TenantMembershipRepo, TenantMembershipStore, TransientTokenRepo, TransientTokenStore,
};
use crate::middleware::TenantId;
use crate::proto::iam::v1::{
    BrowserSession, CreateLoginFlowRequest, CreateLogoutFlowRequest, CreateRecoveryFlowRequest,
    CreateRegistrationFlowRequest, CreateSettingsFlowRequest, CreateVerificationFlowRequest,
    FlowError, GetFlowErrorRequest, GetFlowRequest, GetTenantCapabilitiesRequest,
    GetTenantCapabilitiesResponse, IdentitySelfService, LogoutFlow, OAuth2LoginRequest,
    SelfServiceFlow, SubmitFlowRequest, SubmitLogoutFlowRequest, SubmitRecoveryTokenRequest,
    SubmitRecoveryTokenResponse, SubmitVerificationTokenRequest, SubmitVerificationTokenResponse,
    TenantCapabilities, ToSessionRequest, WebAuthnJsResponse,
};
use crate::services::identity::{extract_email, normalize_traits, validate_traits};
use buffa_types::google::protobuf::Empty;

const BACKEND_KRATOS: &str = "kratos";
const BACKEND_HYDRA: &str = "hydra";

fn transient_expiry() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::hours(1)
}

/// Resolve a login challenge supplied by the caller to the Hydra challenge that
/// Kratos expects.
///
/// The gateway mints its own opaque login challenges (see
/// `map_oauth2_login_request`) so that Hydra identifiers never leave the
/// gateway in protocol artifacts. When the caller presents such a gateway
/// challenge, the transient token store resolves it back to the Hydra
/// challenge.
///
/// However, the standard Ory login flow also delivers Hydra's raw challenge to
/// the login UI via the `login_challenge` query parameter of Hydra's redirect.
/// In that case the value is already the Hydra challenge and there is no
/// mapping to resolve. Kratos accepts the raw value unchanged, so on a lookup
/// miss we pass it through rather than failing with `not_found`. Kratos still
/// cryptographically validates the challenge, so passthrough is safe.
async fn resolve_login_challenge(
    transient: &dyn TransientTokenStore,
    tenant_id: &str,
    login_challenge: &str,
) -> Result<String, ServiceError> {
    match transient
        .get_ory_token(
            tenant_id,
            BACKEND_HYDRA,
            TOKEN_TYPE_LOGIN_CHALLENGE,
            login_challenge,
        )
        .await
    {
        Ok(ory_challenge) => Ok(ory_challenge),
        Err(DbError::MappingNotFound) => Ok(login_challenge.to_string()),
        Err(err) => Err(err.into()),
    }
}

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
        flow: &str,
        cookie: Option<&str>,
        csrf_token: Option<&str>,
    ) -> Result<sso_ory_client::kratos::KratosRedirectResponse, OryClientError>;

    async fn submit_verification_token(
        &self,
        token: &str,
        flow: &str,
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
        flow: &str,
        cookie: Option<&str>,
        csrf_token: Option<&str>,
    ) -> Result<sso_ory_client::kratos::KratosRedirectResponse, OryClientError> {
        self.submit_recovery_token(token, flow, cookie, csrf_token)
            .await
    }

    async fn submit_verification_token(
        &self,
        token: &str,
        flow: &str,
        cookie: Option<&str>,
        csrf_token: Option<&str>,
    ) -> Result<sso_ory_client::kratos::KratosRedirectResponse, OryClientError> {
        self.submit_verification_token(token, flow, cookie, csrf_token)
            .await
    }
}

/// Async trait abstracting the Hydra login-request operations used by this
/// service. Keeps the service implementation decoupled from the concrete HTTP
/// client so unit tests can inject stubs.
#[async_trait]
pub trait LoginHydra: Send + Sync {
    async fn get_login_request(&self, challenge: &str) -> Result<Value, OryClientError>;

    async fn accept_login_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError>;
}

#[async_trait]
impl LoginHydra for HydraClient {
    async fn get_login_request(&self, challenge: &str) -> Result<Value, OryClientError> {
        self.get_login_request(challenge).await
    }

    async fn accept_login_request(
        &self,
        challenge: &str,
        body: Value,
    ) -> Result<Value, OryClientError> {
        self.accept_login_request(challenge, body).await
    }
}

#[derive(Clone)]
pub struct IdentitySelfServiceImpl {
    kratos: Arc<dyn KratosSelfService>,
    hydra: Arc<dyn LoginHydra>,
    transient: Arc<dyn TransientTokenStore>,
    mappings: Arc<dyn IdMappingStore>,
    schemas: Arc<dyn IdentitySchemaStore>,
    memberships: Arc<dyn TenantMembershipStore>,
    consent_enabled: bool,
    kratos_public_url: String,
    gateway_public_url: String,
    kratos_default_schema_id: String,
}

impl IdentitySelfServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kratos: Arc<KratosClient>,
        hydra: Arc<HydraClient>,
        transient: TransientTokenRepo,
        mappings: IdMappingRepo,
        schemas: IdentitySchemaRepo,
        memberships: TenantMembershipRepo,
        consent_enabled: bool,
        kratos_public_url: String,
        gateway_public_url: String,
        kratos_default_schema_id: String,
    ) -> Self {
        Self {
            kratos: kratos as Arc<dyn KratosSelfService>,
            hydra: hydra as Arc<dyn LoginHydra>,
            transient: Arc::new(transient) as Arc<dyn TransientTokenStore>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            schemas: Arc::new(schemas) as Arc<dyn IdentitySchemaStore>,
            memberships: Arc::new(memberships) as Arc<dyn TenantMembershipStore>,
            consent_enabled,
            kratos_public_url,
            gateway_public_url,
            kratos_default_schema_id,
        }
    }

    /// Replace every non-empty `flow` query parameter in `value` with the
    /// gateway's opaque public flow id, minted (idempotently) through
    /// [`Self::public_flow`]. Unrelated query parameters are preserved.
    ///
    /// Kratos-owned URLs (flow `request_url`, `ui.action`, token-submit
    /// redirect locations, …) embed the raw Kratos flow UUID as
    /// `?flow=<uuid>`; leaking it would expose a backend identifier the
    /// gateway itself cannot resolve. When `strict` is false (flow payload
    /// URLs) a value that does not parse as an absolute URL is returned
    /// unchanged, preserving the historical tolerance of relative or non-URL
    /// strings. When `strict` is true (Kratos token-submit redirect
    /// locations, which must be absolute URLs) a parse failure is
    /// `ServiceError::Internal`.
    async fn scrub_flow_id_in_url(
        &self,
        tenant_id: &str,
        value: &str,
        strict: bool,
    ) -> Result<String, ServiceError> {
        let mut url = match reqwest::Url::parse(value) {
            Ok(url) => url,
            Err(_) if strict => {
                return Err(ServiceError::Internal(
                    "kratos returned an invalid redirect location".into(),
                ));
            }
            Err(_) => return Ok(value.to_string()),
        };
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(key, val)| (key.into_owned(), val.into_owned()))
            .collect();
        // Leave URLs without a scrubbable flow parameter byte-identical.
        if !pairs
            .iter()
            .any(|(key, val)| key == "flow" && !val.is_empty())
        {
            return Ok(value.to_string());
        }
        let mut scrubbed = Vec::with_capacity(pairs.len());
        for (key, val) in pairs {
            if key == "flow" && !val.is_empty() {
                scrubbed.push((key, self.public_flow(tenant_id, &val).await?));
            } else {
                scrubbed.push((key, val));
            }
        }
        url.query_pairs_mut().clear().extend_pairs(scrubbed);
        Ok(url.into())
    }

    /// Apply the Kratos→gateway host rewrite to a Kratos-owned flow URL and
    /// scrub any embedded raw Kratos flow id in one pass.
    async fn rewrite_and_scrub_flow_url(
        &self,
        tenant_id: &str,
        value: &str,
    ) -> Result<String, ServiceError> {
        let rewritten = rewrite_url(value, &self.kratos_public_url, &self.gateway_public_url);
        self.scrub_flow_id_in_url(tenant_id, &rewritten, false)
            .await
    }

    async fn rewrite_flow_urls(
        &self,
        tenant_id: &str,
        flow: &mut SelfServiceFlow,
    ) -> Result<(), ServiceError> {
        // `return_to` is a caller-supplied application URL: host rewrite only,
        // its query parameters are not gateway-owned.
        flow.return_to = rewrite_url(
            &flow.return_to,
            &self.kratos_public_url,
            &self.gateway_public_url,
        );
        flow.request_url = self
            .rewrite_and_scrub_flow_url(tenant_id, &flow.request_url)
            .await?;
        if let Some(ui) = flow.ui.as_option_mut() {
            ui.action = self
                .rewrite_and_scrub_flow_url(tenant_id, &ui.action)
                .await?;
            for node in &mut ui.nodes {
                if let Some(crate::proto::iam::v1::ui_node::Attributes::Anchor(attrs)) =
                    node.attributes.as_mut()
                {
                    attrs.href = self
                        .rewrite_and_scrub_flow_url(tenant_id, &attrs.href)
                        .await?;
                }
                if let Some(crate::proto::iam::v1::ui_node::Attributes::Image(attrs)) =
                    node.attributes.as_mut()
                {
                    attrs.src = self
                        .rewrite_and_scrub_flow_url(tenant_id, &attrs.src)
                        .await?;
                }
                if let Some(crate::proto::iam::v1::ui_node::Attributes::Script(attrs)) =
                    node.attributes.as_mut()
                {
                    attrs.src = self
                        .rewrite_and_scrub_flow_url(tenant_id, &attrs.src)
                        .await?;
                }
                if let Some(crate::proto::iam::v1::ui_node::Attributes::Input(attrs)) =
                    node.attributes.as_mut()
                {
                    attrs.src = self
                        .rewrite_and_scrub_flow_url(tenant_id, &attrs.src)
                        .await?;
                }
            }
        }
        // OAuth2 client URIs are application-owned URLs: host rewrite only,
        // they may legitimately carry unrelated `flow` parameters.
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
        Ok(())
    }

    async fn resolve_flow(
        &self,
        tenant_id: &str,
        public_flow_id: &str,
    ) -> Result<String, ServiceError> {
        if public_flow_id.is_empty() {
            return Err(ServiceError::InvalidArgument("flow id is required".into()));
        }
        self.transient
            .get_ory_token(tenant_id, BACKEND_KRATOS, TOKEN_TYPE_FLOW, public_flow_id)
            .await
            .map_err(|e| e.into())
    }

    async fn public_flow(
        &self,
        tenant_id: &str,
        ory_flow_id: &str,
    ) -> Result<String, ServiceError> {
        if ory_flow_id.is_empty() {
            return Ok(String::new());
        }
        self.transient
            .create(
                tenant_id,
                BACKEND_KRATOS,
                TOKEN_TYPE_FLOW,
                ory_flow_id,
                transient_expiry(),
            )
            .await
            .map_err(|e| e.into())
    }

    async fn map_flow_response(
        &self,
        tenant_id: &str,
        flow: &mut SelfServiceFlow,
    ) -> Result<(), ServiceError> {
        flow.id = self.public_flow(tenant_id, &flow.id).await?;
        // Kratos echoes its own (base) schema id on settings flows. Surface the
        // tenant's gateway schema instead, and never leak the Kratos id.
        if !flow.identity_schema_id.is_empty() {
            flow.identity_schema_id = match self.schemas.get_default(tenant_id).await {
                Ok(schema) => schema.schema_id,
                Err(_) => String::new(),
            };
        }
        if let Some(oauth2) = flow.oauth2_login_request.as_option_mut() {
            self.map_oauth2_login_request(tenant_id, oauth2).await?;
        }
        Ok(())
    }

    async fn map_oauth2_login_request(
        &self,
        tenant_id: &str,
        oauth2: &mut OAuth2LoginRequest,
    ) -> Result<(), ServiceError> {
        if !oauth2.challenge.is_empty() {
            oauth2.challenge = self
                .transient
                .create(
                    tenant_id,
                    BACKEND_HYDRA,
                    TOKEN_TYPE_LOGIN_CHALLENGE,
                    &oauth2.challenge,
                    transient_expiry(),
                )
                .await?;
        }
        if !oauth2.client_id.is_empty() {
            oauth2.client_id = self
                .mappings
                .get_public_id(tenant_id, BACKEND_HYDRA, &oauth2.client_id)
                .await?;
        }
        if !oauth2.subject.is_empty() {
            oauth2.subject = self
                .mappings
                .get_public_id(tenant_id, BACKEND_KRATOS, &oauth2.subject)
                .await?;
        }
        if let Some(client) = oauth2.client.as_option_mut()
            && !client.client_id.is_empty()
        {
            client.client_id = self
                .mappings
                .get_public_id(tenant_id, BACKEND_HYDRA, &client.client_id)
                .await?;
        }
        Ok(())
    }

    /// Accept the Hydra login request with the caller's existing session when
    /// Hydra reports the login may be skipped.
    ///
    /// Kratos' browser login route does the same server-side: with a valid
    /// session and a `login_challenge` whose Hydra login request has `skip`
    /// set, it accepts the login with Hydra and redirects the browser to
    /// Hydra's `redirect_to`. On the JSON content-negotiation path, however,
    /// Kratos discards that redirect and answers with a bare
    /// `session_already_available` error — after having already consumed the
    /// challenge. API callers (the login UI via this gateway) then cannot
    /// complete the OAuth2 flow and fall back to a logout-and-retry dance.
    /// Mirror the browser behavior here so the challenge is accepted exactly
    /// once, with the current session's subject.
    ///
    /// Returns `Ok(None)` when normal Kratos flow creation should proceed: the
    /// login request could not be fetched (Kratos surfaces the same failure
    /// when it fetches the request itself), its `skip` flag is unset (Hydra
    /// wants authentication; Kratos forces a refresh flow), or the caller has
    /// no valid Kratos session to accept with.
    async fn accept_skippable_login(
        &self,
        ory_challenge: &str,
        cookie: Option<&str>,
    ) -> Result<Option<SelfServiceFlow>, ServiceError> {
        let login_request = match self.hydra.get_login_request(ory_challenge).await {
            Ok(request) => request,
            Err(err) => {
                tracing::debug!(?err, "hydra login request fetch failed; creating kratos flow");
                return Ok(None);
            }
        };
        if !login_request
            .get("skip")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let Some(cookie) = cookie else {
            return Ok(None);
        };
        let session = match self.kratos.to_session(Some(cookie), None).await {
            Ok(session) => session,
            Err(_) => return Ok(None),
        };
        let subject = session
            .pointer("/identity/id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if subject.is_empty() {
            return Ok(None);
        }
        let amr: Vec<String> = session
            .get("authentication_methods")
            .and_then(Value::as_array)
            .map(|methods| {
                methods
                    .iter()
                    .filter_map(|method| {
                        method
                            .get("method")
                            .and_then(Value::as_str)
                            .map(String::from)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut accept_body = serde_json::json!({
            "subject": subject,
            "amr": amr,
        });
        if let Some(session_id) = session.get("id").and_then(Value::as_str) {
            accept_body["identity_provider_session_id"] = Value::String(session_id.to_string());
        }
        let accept = self
            .hydra
            .accept_login_request(ory_challenge, accept_body)
            .await
            .map_err(map_ory_error)?;
        let redirect_to = accept
            .get("redirect_to")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if redirect_to.is_empty() {
            return Err(ServiceError::Internal(
                "hydra accept login response missing redirect_to".into(),
            ));
        }
        Ok(Some(SelfServiceFlow {
            redirect_browser_to: redirect_to,
            ..Default::default()
        }))
    }

    /// Map a Kratos submit outcome to a public flow response.
    ///
    /// A successful submit returns the flow body as usual. A submit that
    /// completes with Kratos' `browser_location_change_required` (surfaced by
    /// the client as [`OryClientError::Redirect`]) returns a flow carrying only
    /// `redirect_browser_to`; the Kratos session cookie that rides on that 422
    /// is attached to the response so the browser session is established. The
    /// location is already a browser-reachable URL, so it is passed through
    /// unchanged. Any other error is mapped normally.
    async fn map_submit_response(
        &self,
        tenant_id: &str,
        result: Result<KratosResponse, OryClientError>,
    ) -> ServiceResult<SelfServiceFlow> {
        let flow = match result {
            Ok(flow) => flow,
            Err(OryClientError::Redirect {
                location,
                set_cookies,
            }) => {
                let body = SelfServiceFlow {
                    redirect_browser_to: location,
                    ..Default::default()
                };
                let mut response = Response::new(body);
                attach_set_cookie_values(&mut response, &set_cookies);
                return Ok(response);
            }
            Err(err) => return Err(map_ory_error(err).into()),
        };
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.map_flow_response(tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(tenant_id, &mut response.body)
            .await?;
        attach_set_cookies(&mut response, &flow.headers);
        Ok(response)
    }

    /// Intercept a settings-flow profile update so the gateway stays the trait owner.
    ///
    /// Profile (traits) submissions are normalized, validated against the membership's
    /// schema, merged into the membership, and reduced to `{email}` before reaching
    /// Kratos. Email is immutable. Non-profile methods (password, oidc, webauthn, …)
    /// carry no `traits` object and pass through untouched — credentials stay in Kratos.
    async fn intercept_settings_profile(
        &self,
        tenant_id: &str,
        cookie: Option<&str>,
        body: &mut serde_json::Value,
    ) -> Result<(), ServiceError> {
        let submitted = match body.get("traits").and_then(|t| t.as_object()) {
            Some(obj) => serde_json::Value::Object(obj.clone()),
            None => return Ok(()),
        };

        let session = self
            .kratos
            .to_session(cookie, None)
            .await
            .map_err(map_ory_error)?;
        let ory_identity_id = session
            .get("identity")
            .and_then(|i| i["id"].as_str())
            .unwrap_or("");
        if ory_identity_id.is_empty() {
            return Err(ServiceError::Unauthenticated(
                "settings flow has no authenticated identity".into(),
            ));
        }
        let public_id = self
            .mappings
            .get_public_id(tenant_id, BACKEND_KRATOS, ory_identity_id)
            .await?;

        let membership = match self.memberships.get(tenant_id, &public_id).await {
            Ok(membership) => membership,
            Err(DbError::MembershipNotFound) => {
                // Pre-migration identity: backfill a membership from the session under the
                // tenant's default gateway schema so this write becomes authoritative.
                let schema = self.schemas.get_default(tenant_id).await?;
                let email = session
                    .get("identity")
                    .and_then(|i| i["traits"]["email"].as_str())
                    .unwrap_or("")
                    .to_string();
                self.memberships
                    .upsert(
                        tenant_id,
                        &public_id,
                        &schema.schema_id,
                        schema.version,
                        serde_json::json!({ "email": email }),
                    )
                    .await?
            }
            Err(err) => return Err(err.into()),
        };

        let schema = self
            .schemas
            .get_by_schema_id(tenant_id, &membership.schema_id)
            .await?;

        let mut submitted = submitted;
        normalize_traits(&mut submitted);
        validate_traits(&schema.schema_json, &submitted)?;
        let new_email = extract_email(&submitted)?;

        let current_email = membership
            .traits
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !current_email.is_empty() && new_email != current_email {
            return Err(ServiceError::InvalidArgument("email is immutable".into()));
        }

        // The gateway is authoritative for traits: overlay the submitted fields onto the
        // stored membership traits, then pin the email to its immutable value.
        let mut merged = membership.traits.clone();
        if let (Some(m), Some(s)) = (merged.as_object_mut(), submitted.as_object()) {
            for (key, value) in s.iter() {
                m.insert(key.clone(), value.clone());
            }
        }
        if let Some(m) = merged.as_object_mut() {
            m.insert(
                "email".to_string(),
                serde_json::json!(current_email.clone()),
            );
        }
        self.memberships
            .upsert(
                tenant_id,
                &public_id,
                &membership.schema_id,
                membership.schema_version,
                merged,
            )
            .await?;

        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "traits".to_string(),
                serde_json::json!({ "email": current_email }),
            );
        }
        Ok(())
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

/// Attach raw `Set-Cookie` header values captured from an upstream response
/// (e.g. a Kratos `browser_location_change_required` redirect) to the outgoing
/// response. Values that fail to parse as header values are skipped.
fn attach_set_cookie_values<T>(response: &mut Response<T>, set_cookies: &[String]) {
    for cookie in set_cookies {
        if let Ok(value) = http::HeaderValue::from_str(cookie) {
            response.headers.append("set-cookie", value);
        }
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
        let tenant_id = tenant_from_context(&ctx);
        proto.tenant_id = tenant_id.clone();
        if !tenant_id.is_empty() {
            let ory_session_id = session["id"].as_str().unwrap_or("");
            if !ory_session_id.is_empty() {
                proto.id = self
                    .transient
                    .create(
                        &tenant_id,
                        BACKEND_KRATOS,
                        TOKEN_TYPE_SESSION,
                        ory_session_id,
                        transient_expiry(),
                    )
                    .await?;
            }
            let ory_identity_id = session
                .get("identity")
                .and_then(|i| i["id"].as_str())
                .unwrap_or("");
            if !ory_identity_id.is_empty() {
                proto.identity_id = self
                    .mappings
                    .get_public_id(&tenant_id, BACKEND_KRATOS, ory_identity_id)
                    .await?;
                if let Some(identity) = proto.identity.as_option_mut() {
                    identity.id = proto.identity_id.clone();
                }
            }
        }
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
        let tenant_id = tenant_from_context(&ctx);
        let ory_flow_id = self.resolve_flow(&tenant_id, &req.id).await?;
        let flow = self
            .kratos
            .get_login_flow(&ory_flow_id, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.map_flow_response(&tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(&tenant_id, &mut response.body)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
        let ory_flow_id = self.resolve_flow(&tenant_id, &req.id).await?;
        let flow = self
            .kratos
            .get_registration_flow(&ory_flow_id, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.map_flow_response(&tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(&tenant_id, &mut response.body)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
        let ory_flow_id = self.resolve_flow(&tenant_id, &req.id).await?;
        let flow = self
            .kratos
            .get_settings_flow(&ory_flow_id, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.map_flow_response(&tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(&tenant_id, &mut response.body)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
        let ory_flow_id = self.resolve_flow(&tenant_id, &req.id).await?;
        let flow = self
            .kratos
            .get_recovery_flow(&ory_flow_id, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.map_flow_response(&tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(&tenant_id, &mut response.body)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
        let ory_flow_id = self.resolve_flow(&tenant_id, &req.id).await?;
        let flow = self
            .kratos
            .get_verification_flow(&ory_flow_id, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.map_flow_response(&tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(&tenant_id, &mut response.body)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
        let body = proto_struct_to_json(req.body.as_option());
        let ory_flow_id = self.resolve_flow(&tenant_id, &req.id).await?;
        let result = self
            .kratos
            .submit_login_flow(&ory_flow_id, cookie.as_deref(), body)
            .await;
        self.map_submit_response(&tenant_id, result).await
    }

    #[instrument(skip(self, request))]
    async fn submit_registration_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let tenant_id = tenant_from_context(&ctx);
        let body = proto_struct_to_json(req.body.as_option());
        let ory_flow_id = self.resolve_flow(&tenant_id, &req.id).await?;
        let result = self
            .kratos
            .submit_registration_flow(&ory_flow_id, cookie.as_deref(), body)
            .await;
        self.map_submit_response(&tenant_id, result).await
    }

    #[instrument(skip(self, request))]
    async fn submit_settings_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let tenant_id = tenant_from_context(&ctx);
        let mut body = proto_struct_to_json(req.body.as_option());
        let ory_flow_id = self.resolve_flow(&tenant_id, &req.id).await?;
        self.intercept_settings_profile(&tenant_id, cookie.as_deref(), &mut body)
            .await?;
        let result = self
            .kratos
            .submit_settings_flow(&ory_flow_id, cookie.as_deref(), body)
            .await;
        self.map_submit_response(&tenant_id, result).await
    }

    #[instrument(skip(self, request))]
    async fn submit_recovery_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let tenant_id = tenant_from_context(&ctx);
        let body = proto_struct_to_json(req.body.as_option());
        let ory_flow_id = self.resolve_flow(&tenant_id, &req.id).await?;
        let result = self
            .kratos
            .submit_recovery_flow(&ory_flow_id, cookie.as_deref(), body)
            .await;
        self.map_submit_response(&tenant_id, result).await
    }

    #[instrument(skip(self, request))]
    async fn submit_verification_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let tenant_id = tenant_from_context(&ctx);
        let body = proto_struct_to_json(req.body.as_option());
        let ory_flow_id = self.resolve_flow(&tenant_id, &req.id).await?;
        let result = self
            .kratos
            .submit_verification_flow(&ory_flow_id, cookie.as_deref(), body)
            .await;
        self.map_submit_response(&tenant_id, result).await
    }

    #[instrument(skip(self, request))]
    async fn create_login_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateLoginFlowRequest>,
    ) -> ServiceResult<SelfServiceFlow> {
        let req = request.to_owned_message();
        let cookie = cookie_from_context(&ctx);
        let tenant_id = tenant_from_context(&ctx);
        let mut query_owned = Vec::<(&str, String)>::new();
        if !req.return_to.is_empty() {
            query_owned.push(("return_to", req.return_to));
        }
        if !req.aal.is_empty() {
            query_owned.push(("aal", req.aal));
        }
        if req.refresh {
            query_owned.push(("refresh", "true".to_string()));
        }
        if !req.organization.is_empty() {
            query_owned.push(("organization", req.organization));
        }
        if !req.via.is_empty() {
            query_owned.push(("via", req.via));
        }
        if !req.login_challenge.is_empty() {
            let ory_challenge =
                resolve_login_challenge(self.transient.as_ref(), &tenant_id, &req.login_challenge)
                    .await?;
            if let Some(flow) = self
                .accept_skippable_login(&ory_challenge, cookie.as_deref())
                .await?
            {
                return Ok(Response::new(flow));
            }
            query_owned.push(("login_challenge", ory_challenge));
        }
        if !req.identity_schema.is_empty() {
            query_owned.push(("identity_schema", self.kratos_default_schema_id.clone()));
        }
        let query_refs: Vec<(&str, &str)> =
            query_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let flow = self
            .kratos
            .create_login_browser_flow(&query_refs, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.map_flow_response(&tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(&tenant_id, &mut response.body)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
        let mut query_owned = Vec::<(&str, String)>::new();
        if !req.return_to.is_empty() {
            query_owned.push(("return_to", req.return_to));
        }
        if !req.login_challenge.is_empty() {
            let ory_challenge =
                resolve_login_challenge(self.transient.as_ref(), &tenant_id, &req.login_challenge)
                    .await?;
            query_owned.push(("login_challenge", ory_challenge));
        }
        if !req.identity_schema.is_empty() {
            query_owned.push(("identity_schema", self.kratos_default_schema_id.clone()));
        }
        let query_refs: Vec<(&str, &str)> =
            query_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let flow = self
            .kratos
            .create_registration_browser_flow(&query_refs, cookie.as_deref())
            .await
            .map_err(map_ory_error)?;
        let mut response = Response::new(ory_flow_to_proto(&flow.body));
        self.map_flow_response(&tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(&tenant_id, &mut response.body)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
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
        self.map_flow_response(&tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(&tenant_id, &mut response.body)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
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
        self.map_flow_response(&tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(&tenant_id, &mut response.body)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
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
        if !response.body.logout_token.is_empty() {
            response.body.logout_token = self
                .transient
                .create(
                    &tenant_id,
                    BACKEND_KRATOS,
                    TOKEN_TYPE_LOGOUT_TOKEN,
                    &response.body.logout_token,
                    transient_expiry(),
                )
                .await?;
        }
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
        let tenant_id = tenant_from_context(&ctx);
        let return_to = if req.return_to.is_empty() {
            None
        } else {
            Some(req.return_to.as_str())
        };
        let ory_token = self
            .transient
            .get_ory_token(
                &tenant_id,
                BACKEND_KRATOS,
                TOKEN_TYPE_LOGOUT_TOKEN,
                &req.token,
            )
            .await?;
        self.kratos
            .submit_logout_flow(&ory_token, return_to, cookie.as_deref())
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
        let tenant_id = tenant_from_context(&ctx);
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
        self.map_flow_response(&tenant_id, &mut response.body)
            .await?;
        self.rewrite_flow_urls(&tenant_id, &mut response.body)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
        if req.flow.is_empty() {
            return Err(ServiceError::InvalidArgument(
                "flow is required to exchange a recovery token".into(),
            )
            .into());
        }
        let ory_token = self
            .transient
            .get_ory_token(
                &tenant_id,
                BACKEND_KRATOS,
                TOKEN_TYPE_RECOVERY_TOKEN,
                &req.token,
            )
            .await?;
        let ory_flow = self
            .transient
            .get_ory_token(&tenant_id, BACKEND_KRATOS, TOKEN_TYPE_FLOW, &req.flow)
            .await?;
        let redirect = self
            .kratos
            .submit_recovery_token(
                &ory_token,
                &ory_flow,
                cookie.as_deref(),
                csrf_token.as_deref(),
            )
            .await
            .map_err(map_ory_error)?;
        let redirect_to = redirect.location.ok_or_else(|| {
            ServiceError::Internal("kratos recovery token response missing location".into())
        })?;
        let redirect_to = self
            .scrub_flow_id_in_url(&tenant_id, &redirect_to, true)
            .await?;
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
        let tenant_id = tenant_from_context(&ctx);
        if req.flow.is_empty() {
            return Err(ServiceError::InvalidArgument(
                "flow is required to exchange a verification token".into(),
            )
            .into());
        }
        let ory_token = self
            .transient
            .get_ory_token(
                &tenant_id,
                BACKEND_KRATOS,
                TOKEN_TYPE_VERIFICATION_TOKEN,
                &req.token,
            )
            .await?;
        let ory_flow = self
            .transient
            .get_ory_token(&tenant_id, BACKEND_KRATOS, TOKEN_TYPE_FLOW, &req.flow)
            .await?;
        let redirect = self
            .kratos
            .submit_verification_token(
                &ory_token,
                &ory_flow,
                cookie.as_deref(),
                csrf_token.as_deref(),
            )
            .await
            .map_err(map_ory_error)?;
        let redirect_to = redirect.location.ok_or_else(|| {
            ServiceError::Internal("kratos verification token response missing location".into())
        })?;
        let redirect_to = self
            .scrub_flow_id_in_url(&tenant_id, &redirect_to, true)
            .await?;
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
        ctx: RequestContext,
        request: ServiceRequest<'_, GetFlowErrorRequest>,
    ) -> ServiceResult<FlowError> {
        let req = request.to_owned_message();
        let tenant_id = tenant_from_context(&ctx);
        let ory_error_id = self
            .transient
            .get_ory_token(&tenant_id, BACKEND_KRATOS, TOKEN_TYPE_FLOW, &req.id)
            .await?;
        let error = self
            .kratos
            .get_flow_error(&ory_error_id)
            .await
            .map_err(map_ory_error)?;
        let mut proto = ory_flow_error_to_proto(&error);
        if !proto.id.is_empty() {
            proto.id = self.public_flow(&tenant_id, &proto.id).await?;
        }
        Ok(Response::new(proto))
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
        OryClientError::Redirect { .. } => ServiceError::Internal("unexpected redirect".into()),
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

    use crate::db::{
        DbError, IdMappingRow, IdMappingStore, IdentitySchemaRow, IdentitySchemaStore,
        TOKEN_TYPE_FLOW, TOKEN_TYPE_LOGIN_CHALLENGE, TOKEN_TYPE_LOGOUT_TOKEN,
        TOKEN_TYPE_RECOVERY_TOKEN, TOKEN_TYPE_SESSION, TOKEN_TYPE_VERIFICATION_TOKEN,
        TenantMembershipRow, TenantMembershipStore, TransientTokenRow, TransientTokenStore,
    };
    use crate::middleware::TenantId;
    use crate::proto::iam::v1::{
        CreateLoginFlowRequest, CreateLogoutFlowRequest, CreateRecoveryFlowRequest,
        CreateRegistrationFlowRequest, CreateSettingsFlowRequest, CreateVerificationFlowRequest,
        GetFlowErrorRequest, GetFlowRequest, GetTenantCapabilitiesRequest, IdentitySelfService,
        SelfServiceFlow, SubmitFlowRequest, SubmitLogoutFlowRequest, SubmitRecoveryTokenRequest,
        SubmitVerificationTokenRequest, ToSessionRequest,
    };
    use ulid::Ulid;

    use super::{
        BACKEND_HYDRA, BACKEND_KRATOS, IdentitySelfServiceImpl, KratosSelfService, LoginHydra,
        cookie_from_context, csrf_token_from_context, map_ory_error, tenant_from_context,
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

        fn reseed_flow_redirect(&self, location: &str, cookies: &[&str]) {
            *self.flow.lock().unwrap() = Some(Err(OryClientError::Redirect {
                location: location.to_string(),
                set_cookies: cookies.iter().map(|c| c.to_string()).collect(),
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
            flow: &str,
            cookie: Option<&str>,
            csrf_token: Option<&str>,
        ) -> Result<KratosRedirectResponse, OryClientError> {
            self.record(format!(
                "submit_recovery_token(token={token}, flow={flow}, cookie={:?}, csrf_token={:?})",
                cookie, csrf_token
            ));
            self.take_token_submit()
        }

        async fn submit_verification_token(
            &self,
            token: &str,
            flow: &str,
            cookie: Option<&str>,
            csrf_token: Option<&str>,
        ) -> Result<KratosRedirectResponse, OryClientError> {
            self.record(format!(
                "submit_verification_token(token={token}, flow={flow}, cookie={:?}, csrf_token={:?})",
                cookie, csrf_token
            ));
            self.take_token_submit()
        }
    }

    #[derive(Default, Clone)]
    struct FakeHydra {
        login_request: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        accept_login: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl FakeHydra {
        fn record(&self, call: impl Into<String>) {
            self.calls.lock().unwrap().push(call.into());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl LoginHydra for FakeHydra {
        async fn get_login_request(&self, challenge: &str) -> Result<Value, OryClientError> {
            self.record(format!("get_login_request(challenge={challenge})"));
            self.login_request
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        async fn accept_login_request(
            &self,
            challenge: &str,
            body: Value,
        ) -> Result<Value, OryClientError> {
            self.record(format!(
                "accept_login_request(challenge={challenge}, body={body})"
            ));
            self.accept_login
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
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
        ) -> Result<IdMappingRow, DbError> {
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
            tenant_id: &str,
            backend: &str,
            public_id: &str,
        ) -> Result<String, DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| {
                    r.tenant_id == tenant_id && r.backend == backend && r.public_id == public_id
                })
                .map(|r| r.ory_global_id.clone())
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_public_id(
            &self,
            tenant_id: &str,
            backend: &str,
            ory_global_id: &str,
        ) -> Result<String, DbError> {
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
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_public_id_by_ory_id(
            &self,
            _backend: &str,
            ory_global_id: &str,
        ) -> Result<String, DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.ory_global_id == ory_global_id)
                .map(|r| r.public_id.clone())
                .ok_or(DbError::MappingNotFound)
        }

        async fn delete(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
        ) -> Result<(), DbError> {
            let mut rows = self.rows.lock().unwrap();
            let pos = rows.iter().position(|r| {
                r.tenant_id == tenant_id && r.backend == backend && r.public_id == public_id
            });
            pos.map(|i| rows.remove(i))
                .map(|_| ())
                .ok_or(DbError::MappingNotFound)
        }

        async fn list_public_ids(
            &self,
            tenant_id: &str,
            backend: &str,
        ) -> Result<Vec<String>, DbError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.tenant_id == tenant_id && r.backend == backend)
                .map(|r| r.public_id.clone())
                .collect())
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, DbError> {
            Ok(None)
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
                expires_at: super::transient_expiry(),
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
        ) -> Result<String, DbError> {
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
        ) -> Result<String, DbError> {
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
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_public_token(
            &self,
            _tenant_id: &str,
            backend: &str,
            token_type: &str,
            ory_token: &str,
        ) -> Result<String, DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| {
                    r.backend == backend && r.token_type == token_type && r.ory_token == ory_token
                })
                .map(|r| r.public_token.clone())
                .ok_or(DbError::MappingNotFound)
        }

        async fn delete(&self, _tenant_id: &str, public_token: &str) -> Result<(), DbError> {
            let mut rows = self.rows.lock().unwrap();
            let pos = rows.iter().position(|r| r.public_token == public_token);
            pos.map(|i| rows.remove(i))
                .map(|_| ())
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_ory_token_global(
            &self,
            backend: &str,
            token_type: &str,
            public_token: &str,
        ) -> Result<(String, String), DbError> {
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
                .ok_or(DbError::MappingNotFound)
        }
    }

    fn default_mapping_store() -> StubMappingStore {
        StubMappingStore::default()
            .with_mapping("tenant-1", BACKEND_KRATOS, "pub-identity-1", "identity-1")
            .with_mapping("tenant-1", BACKEND_HYDRA, "pub-client-1", "client-1")
    }

    fn default_transient_store() -> StubTransientTokenStore {
        let store = StubTransientTokenStore::default();
        store.seed("", BACKEND_KRATOS, TOKEN_TYPE_FLOW, "flow-1", "flow-1");
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_FLOW,
            "registration-flow",
            "registration-flow",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_FLOW,
            "settings-flow",
            "settings-flow",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_FLOW,
            "recovery-flow",
            "recovery-flow",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_FLOW,
            "recovery-flow-1",
            "recovery-flow-1",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_FLOW,
            "verification-flow",
            "verification-flow",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_FLOW,
            "verification-flow-1",
            "verification-flow-1",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_FLOW,
            "pub-error-1",
            "error-1",
        );
        store.seed("", BACKEND_KRATOS, TOKEN_TYPE_FLOW, "error-1", "error-1");
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_SESSION,
            "session-1",
            "session-1",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_LOGOUT_TOKEN,
            "pub-logout-token",
            "token-1",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_LOGOUT_TOKEN,
            "token-1",
            "token-1",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_RECOVERY_TOKEN,
            "pub-recovery-token-1",
            "recovery-token-1",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_RECOVERY_TOKEN,
            "recovery-token-1",
            "recovery-token-1",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_RECOVERY_TOKEN,
            "pub-recovery-token",
            "recovery-token",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_RECOVERY_TOKEN,
            "recovery-token",
            "recovery-token",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_RECOVERY_TOKEN,
            "token",
            "token",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_RECOVERY_TOKEN,
            "expired",
            "expired",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_VERIFICATION_TOKEN,
            "pub-verification-token-1",
            "verification-token-1",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_VERIFICATION_TOKEN,
            "verification-token-1",
            "verification-token-1",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_VERIFICATION_TOKEN,
            "pub-verification-token",
            "verification-token",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_VERIFICATION_TOKEN,
            "verification-token",
            "verification-token",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_VERIFICATION_TOKEN,
            "token",
            "token",
        );
        store.seed(
            "",
            BACKEND_KRATOS,
            TOKEN_TYPE_VERIFICATION_TOKEN,
            "missing",
            "missing",
        );
        store.seed(
            "",
            BACKEND_HYDRA,
            TOKEN_TYPE_LOGIN_CHALLENGE,
            "challenge-1",
            "challenge-1",
        );
        store
    }

    #[derive(Clone, Default)]
    struct StubSchemaStore {
        get_default_result: Arc<Mutex<Option<Result<IdentitySchemaRow, DbError>>>>,
    }

    impl StubSchemaStore {
        fn with_default(row: IdentitySchemaRow) -> Self {
            Self {
                get_default_result: Arc::new(Mutex::new(Some(Ok(row)))),
            }
        }

        fn with_default_error(err: DbError) -> Self {
            Self {
                get_default_result: Arc::new(Mutex::new(Some(Err(err)))),
            }
        }
    }

    #[async_trait::async_trait]
    impl IdentitySchemaStore for StubSchemaStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
            _schema_json: serde_json::Value,
            _is_default: bool,
        ) -> Result<IdentitySchemaRow, DbError> {
            unimplemented!()
        }

        async fn get_by_schema_id(
            &self,
            tenant_id: &str,
            schema_id: &str,
        ) -> Result<IdentitySchemaRow, DbError> {
            Ok(IdentitySchemaRow {
                id: "schema-1".into(),
                tenant_id: tenant_id.to_string(),
                schema_id: schema_id.to_string(),
                schema_json: json!({}),
                version: 1,
                is_default: true,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })
        }

        async fn list(&self, _tenant_id: &str) -> Result<Vec<IdentitySchemaRow>, DbError> {
            unimplemented!()
        }

        async fn delete(&self, _tenant_id: &str, _schema_id: &str) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn update(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
            _schema_json: serde_json::Value,
            _is_default: bool,
        ) -> Result<IdentitySchemaRow, DbError> {
            unimplemented!()
        }

        async fn set_default(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
        ) -> Result<IdentitySchemaRow, DbError> {
            unimplemented!()
        }

        async fn get_default(&self, tenant_id: &str) -> Result<IdentitySchemaRow, DbError> {
            match self.get_default_result.lock().unwrap().take() {
                Some(result) => result,
                None => Ok(IdentitySchemaRow {
                    id: "schema-1".into(),
                    tenant_id: tenant_id.to_string(),
                    schema_id: "default".into(),
                    schema_json: json!({}),
                    version: 1,
                    is_default: true,
                    created_at: time::OffsetDateTime::now_utc(),
                    updated_at: time::OffsetDateTime::now_utc(),
                }),
            }
        }
    }

    fn default_schema_store() -> StubSchemaStore {
        StubSchemaStore::default()
    }

    type MembershipUpsertCall = (String, String, String, i64, serde_json::Value);

    #[derive(Clone, Default)]
    struct StubMembershipStore {
        get_result: Arc<Mutex<Option<Result<TenantMembershipRow, DbError>>>>,
        upsert_calls: Arc<Mutex<Vec<MembershipUpsertCall>>>,
    }

    impl StubMembershipStore {
        fn with_membership(row: TenantMembershipRow) -> Self {
            Self {
                get_result: Arc::new(Mutex::new(Some(Ok(row)))),
                ..Default::default()
            }
        }
    }

    #[async_trait::async_trait]
    impl TenantMembershipStore for StubMembershipStore {
        async fn upsert(
            &self,
            tenant_id: &str,
            identity_id: &str,
            schema_id: &str,
            schema_version: i64,
            traits: serde_json::Value,
        ) -> Result<TenantMembershipRow, DbError> {
            self.upsert_calls.lock().unwrap().push((
                tenant_id.to_string(),
                identity_id.to_string(),
                schema_id.to_string(),
                schema_version,
                traits.clone(),
            ));
            let now = time::OffsetDateTime::now_utc();
            Ok(TenantMembershipRow {
                tenant_id: tenant_id.to_string(),
                identity_id: identity_id.to_string(),
                schema_id: schema_id.to_string(),
                schema_version,
                traits,
                state: "active".into(),
                created_at: now,
                updated_at: now,
            })
        }

        async fn get(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
        ) -> Result<TenantMembershipRow, DbError> {
            self.get_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(DbError::MembershipNotFound))
        }

        async fn set_state(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _state: &str,
        ) -> Result<TenantMembershipRow, DbError> {
            unimplemented!()
        }

        async fn list_by_tenant(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<TenantMembershipRow>, DbError> {
            unimplemented!()
        }
    }

    fn default_membership_store() -> StubMembershipStore {
        StubMembershipStore::default()
    }

    fn service(kratos: FakeKratos) -> IdentitySelfServiceImpl {
        service_with_hydra(kratos, FakeHydra::default())
    }

    fn service_with_hydra(kratos: FakeKratos, hydra: FakeHydra) -> IdentitySelfServiceImpl {
        IdentitySelfServiceImpl {
            kratos: Arc::new(kratos),
            hydra: Arc::new(hydra),
            transient: Arc::new(default_transient_store()),
            mappings: Arc::new(default_mapping_store()),
            schemas: Arc::new(default_schema_store()),
            memberships: Arc::new(default_membership_store()),
            consent_enabled: true,
            kratos_public_url: "http://kratos.example.com".to_string(),
            gateway_public_url: "https://gateway.example.com".to_string(),
            kratos_default_schema_id: "default".to_string(),
        }
    }

    #[tokio::test]
    async fn new_stores_kratos_client() {
        let kratos = Arc::new(KratosClient::new("http://localhost:4434").unwrap());
        let hydra = Arc::new(
            sso_ory_client::hydra::HydraClient::new(
                "http://localhost:4445",
                "http://localhost:4444",
            )
            .unwrap(),
        );
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost:5432/unused").unwrap();
        let svc = IdentitySelfServiceImpl::new(
            kratos.clone(),
            hydra,
            crate::db::TransientTokenRepo::new(pool.clone()),
            crate::db::IdMappingRepo::new(pool.clone()),
            crate::db::IdentitySchemaRepo::new(pool.clone()),
            crate::db::TenantMembershipRepo::new(pool),
            true,
            "http://kratos.example.com".to_string(),
            "https://gateway.example.com".to_string(),
            "default".to_string(),
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

    #[tokio::test]
    async fn rewrite_flow_urls_rewrites_ui_action() {
        let svc = service(FakeKratos::default());
        let mut flow = SelfServiceFlow {
            ui: Some(crate::proto::iam::v1::UiContainer {
                action: "http://kratos.example.com/self-service/login?flow=1".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        svc.rewrite_flow_urls("", &mut flow).await.unwrap();
        let action = &flow.ui.as_option().unwrap().action;
        let url = reqwest::Url::parse(action).unwrap();
        assert_eq!(url.host_str(), Some("gateway.example.com"));
        assert_eq!(url.path(), "/self-service/login");
        let flow_param = url
            .query_pairs()
            .find(|(key, _)| key == "flow")
            .map(|(_, val)| val.into_owned())
            .unwrap();
        assert_ne!(flow_param, "1");
        assert!(
            Ulid::from_string(&flow_param).is_ok(),
            "flow param should be a public ULID, got {flow_param}"
        );
    }

    #[tokio::test]
    async fn map_flow_response_surfaces_gateway_schema_and_hides_kratos_schema() {
        let svc = IdentitySelfServiceImpl {
            kratos: Arc::new(FakeKratos::default()),
            hydra: Arc::new(FakeHydra::default()),
            transient: Arc::new(default_transient_store()),
            mappings: Arc::new(default_mapping_store()),
            schemas: Arc::new(StubSchemaStore::with_default(IdentitySchemaRow {
                id: "schema-1".into(),
                tenant_id: "tenant-1".into(),
                schema_id: "gateway-default".into(),
                schema_json: json!({}),
                version: 3,
                is_default: true,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })),
            memberships: Arc::new(default_membership_store()),
            consent_enabled: true,
            kratos_public_url: "http://kratos.example.com".to_string(),
            gateway_public_url: "https://gateway.example.com".to_string(),
            kratos_default_schema_id: "kratos-base".to_string(),
        };
        let mut flow = SelfServiceFlow {
            id: "flow-1".into(),
            identity_schema_id: "kratos-base".into(),
            ..Default::default()
        };
        svc.map_flow_response("tenant-1", &mut flow).await.unwrap();
        assert_eq!(flow.identity_schema_id, "gateway-default");
    }

    #[tokio::test]
    async fn map_flow_response_clears_schema_when_no_gateway_default() {
        let svc = IdentitySelfServiceImpl {
            kratos: Arc::new(FakeKratos::default()),
            hydra: Arc::new(FakeHydra::default()),
            transient: Arc::new(default_transient_store()),
            mappings: Arc::new(default_mapping_store()),
            schemas: Arc::new(StubSchemaStore::with_default_error(DbError::SchemaNotFound)),
            memberships: Arc::new(default_membership_store()),
            consent_enabled: true,
            kratos_public_url: "http://kratos.example.com".to_string(),
            gateway_public_url: "https://gateway.example.com".to_string(),
            kratos_default_schema_id: "kratos-base".to_string(),
        };
        let mut flow = SelfServiceFlow {
            id: "flow-1".into(),
            identity_schema_id: "kratos-base".into(),
            ..Default::default()
        };
        svc.map_flow_response("tenant-1", &mut flow).await.unwrap();
        // The Kratos schema id must never be surfaced, even if no gateway default exists.
        assert!(flow.identity_schema_id.is_empty());
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
        assert_eq!(resp.body.identity_id, "pub-identity-1");
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

    // Regression: a flow id the gateway did not mint (e.g. a raw Kratos UUID
    // that reached the UI via a stale link or a misconfigured redirect) must be
    // rejected with `not_found` and must NOT be forwarded to Kratos. Forwarding
    // it would make Ory's internal flow id a valid gateway input, leaking the
    // backend. The UI re-initializes the flow on `not_found`.
    #[tokio::test]
    async fn get_login_flow_unknown_id_returns_not_found_without_calling_kratos() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(GetFlowRequest {
            id: "b2c3a9db-5129-4156-8f2c-6ad045965953".to_string(),
            ..Default::default()
        });

        let err = svc.get_login_flow(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(
            fake.calls.lock().unwrap().is_empty(),
            "gateway must not forward an unknown flow id to Kratos"
        );
    }

    #[tokio::test]
    async fn submit_login_flow_unknown_id_returns_not_found_without_calling_kratos() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(SubmitFlowRequest {
            id: "b2c3a9db-5129-4156-8f2c-6ad045965953".to_string(),
            ..Default::default()
        });

        let err = svc.submit_login_flow(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(
            fake.calls.lock().unwrap().is_empty(),
            "gateway must not forward an unknown flow id to Kratos"
        );
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
            identity_schema: "employee".to_string(),
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
        // The gateway schema id ("employee") is translated to the Kratos base
        // schema id before it ever reaches Kratos.
        assert!(call.contains("(\"identity_schema\", \"default\")"));
        assert!(!call.contains("employee"));
    }

    // Regression: the standard Ory login flow delivers Hydra's raw challenge to
    // the login UI via the redirect query string. The gateway has no mapping for
    // that value, so it must forward it to Kratos unchanged instead of failing
    // with `not_found` (which previously trapped the browser in a redirect loop).
    #[tokio::test]
    async fn create_login_flow_passes_through_raw_hydra_challenge() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(CreateLoginFlowRequest {
            login_challenge: "raw-hydra-challenge-not-in-store".to_string(),
            ..Default::default()
        });

        svc.create_login_flow(ctx, req).await.unwrap();
        let call = &fake.calls.lock().unwrap()[0];
        assert!(call.starts_with("create_login_browser_flow(query=["));
        assert!(call.contains("(\"login_challenge\", \"raw-hydra-challenge-not-in-store\")"));
    }

    #[tokio::test]
    async fn create_registration_flow_passes_through_raw_hydra_challenge() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(CreateRegistrationFlowRequest {
            login_challenge: "raw-hydra-challenge-not-in-store".to_string(),
            ..Default::default()
        });

        svc.create_registration_flow(ctx, req).await.unwrap();
        let call = &fake.calls.lock().unwrap()[0];
        assert!(call.starts_with("create_registration_browser_flow(query=["));
        assert!(call.contains("(\"login_challenge\", \"raw-hydra-challenge-not-in-store\")"));
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

    // Regression: with an existing Kratos session and a Hydra login request
    // whose `skip` flag is set, Kratos' JSON path answers
    // `session_already_available` after consuming the challenge and dropping
    // Hydra's `redirect_to`, trapping the login UI in a logout-and-retry
    // dance. The gateway must instead accept the login with the current
    // session's subject, mirroring Kratos' browser behavior.
    #[tokio::test]
    async fn create_login_flow_accepts_skippable_login_with_session_subject() {
        let fake = FakeKratos {
            session: Arc::new(Mutex::new(Some(Ok(json!({
                "id": "session-1",
                "active": true,
                "identity": { "id": "identity-1" },
                "authentication_methods": [
                    { "method": "password", "aal": "aal1" },
                    { "method": "totp", "aal": "aal2" }
                ]
            }))))),
            ..Default::default()
        };
        let hydra = FakeHydra {
            login_request: Arc::new(Mutex::new(Some(Ok(json!({
                "challenge": "challenge-1",
                "skip": true
            }))))),
            accept_login: Arc::new(Mutex::new(Some(Ok(json!({
                "redirect_to": "https://hydra.example.com/oauth2/auth?login_verifier=v1"
            }))))),
            ..Default::default()
        };
        let svc = service_with_hydra(fake.clone(), hydra.clone());
        let ctx = request_context_with_cookie("ory_kratos_session=session-1");
        let req = service_request(CreateLoginFlowRequest {
            login_challenge: "challenge-1".to_string(),
            ..Default::default()
        });

        let resp = svc.create_login_flow(ctx, req).await.unwrap();
        assert_eq!(
            resp.body.redirect_browser_to,
            "https://hydra.example.com/oauth2/auth?login_verifier=v1"
        );

        // The challenge is accepted exactly once; Kratos never creates a flow.
        let kratos_calls = fake.calls.lock().unwrap().clone();
        assert!(
            kratos_calls
                .iter()
                .all(|call| !call.starts_with("create_login_browser_flow")),
            "kratos must not create a login flow: {kratos_calls:?}"
        );
        let hydra_calls = hydra.calls();
        assert!(
            hydra_calls
                .iter()
                .any(|call| call == "get_login_request(challenge=challenge-1)")
        );
        let accept_call = hydra_calls
            .iter()
            .find(|call| call.starts_with("accept_login_request(challenge=challenge-1"))
            .expect("login request should be accepted");
        assert!(accept_call.contains("\"subject\":\"identity-1\""));
        assert!(accept_call.contains("\"identity_provider_session_id\":\"session-1\""));
        assert!(accept_call.contains("\"amr\":[\"password\",\"totp\"]"));
    }

    #[tokio::test]
    async fn create_login_flow_proceeds_when_hydra_skip_is_false() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let hydra = FakeHydra {
            login_request: Arc::new(Mutex::new(Some(Ok(json!({
                "challenge": "challenge-1",
                "skip": false
            }))))),
            ..Default::default()
        };
        let svc = service_with_hydra(fake.clone(), hydra.clone());
        let ctx = request_context_with_cookie("ory_kratos_session=session-1");
        let req = service_request(CreateLoginFlowRequest {
            login_challenge: "challenge-1".to_string(),
            ..Default::default()
        });

        let resp = svc.create_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert!(resp.body.redirect_browser_to.is_empty());
        // skip=false means Hydra wants authentication; never accept, never
        // probe the session.
        assert!(
            hydra
                .calls()
                .iter()
                .all(|call| !call.starts_with("accept_login_request"))
        );
        assert!(
            fake.calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call.starts_with("create_login_browser_flow"))
        );
    }

    #[tokio::test]
    async fn create_login_flow_proceeds_when_skip_without_cookie() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let hydra = FakeHydra {
            login_request: Arc::new(Mutex::new(Some(Ok(json!({
                "challenge": "challenge-1",
                "skip": true
            }))))),
            ..Default::default()
        };
        let svc = service_with_hydra(fake.clone(), hydra.clone());
        let ctx = request_context_without_cookie();
        let req = service_request(CreateLoginFlowRequest {
            login_challenge: "challenge-1".to_string(),
            ..Default::default()
        });

        let resp = svc.create_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        // No browser session cookie: nothing to accept with, so Kratos renders
        // the login flow and Hydra is never asked to accept.
        assert!(
            fake.calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| !call.starts_with("to_session"))
        );
        assert!(
            hydra
                .calls()
                .iter()
                .all(|call| !call.starts_with("accept_login_request"))
        );
    }

    #[tokio::test]
    async fn create_login_flow_proceeds_when_session_is_invalid() {
        let fake = FakeKratos {
            session: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 401,
                message: "unauthenticated".into(),
            })))),
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let hydra = FakeHydra {
            login_request: Arc::new(Mutex::new(Some(Ok(json!({
                "challenge": "challenge-1",
                "skip": true
            }))))),
            ..Default::default()
        };
        let svc = service_with_hydra(fake.clone(), hydra.clone());
        let ctx = request_context_with_cookie("ory_kratos_session=stale");
        let req = service_request(CreateLoginFlowRequest {
            login_challenge: "challenge-1".to_string(),
            ..Default::default()
        });

        let resp = svc.create_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert!(
            hydra
                .calls()
                .iter()
                .all(|call| !call.starts_with("accept_login_request"))
        );
    }

    #[tokio::test]
    async fn create_login_flow_proceeds_when_login_request_fetch_fails() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        // Default FakeHydra fails every call; the gateway must fall through
        // and let Kratos surface the failure as it does today.
        let hydra = FakeHydra::default();
        let svc = service_with_hydra(fake.clone(), hydra.clone());
        let ctx = request_context_with_cookie("ory_kratos_session=session-1");
        let req = service_request(CreateLoginFlowRequest {
            login_challenge: "challenge-1".to_string(),
            ..Default::default()
        });

        let resp = svc.create_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert!(
            hydra
                .calls()
                .iter()
                .all(|call| !call.starts_with("accept_login_request"))
        );
        assert!(
            fake.calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call.starts_with("create_login_browser_flow"))
        );
    }

    #[tokio::test]
    async fn create_login_flow_maps_skip_accept_error() {
        let fake = FakeKratos {
            session: Arc::new(Mutex::new(Some(Ok(sample_session())))),
            ..Default::default()
        };
        let hydra = FakeHydra {
            login_request: Arc::new(Mutex::new(Some(Ok(json!({
                "challenge": "challenge-1",
                "skip": true
            }))))),
            accept_login: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 409,
                message: "challenge already used".into(),
            })))),
            ..Default::default()
        };
        let svc = service_with_hydra(fake.clone(), hydra);
        let ctx = request_context_with_cookie("ory_kratos_session=session-1");
        let req = service_request(CreateLoginFlowRequest {
            login_challenge: "challenge-1".to_string(),
            ..Default::default()
        });

        let err = svc.create_login_flow(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::AlreadyExists);
        // A failed accept must not fall through: Kratos would consume the
        // challenge a second time and report session_already_available.
        assert!(
            fake.calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| !call.starts_with("create_login_browser_flow"))
        );
    }

    #[tokio::test]
    async fn create_login_flow_skip_accept_missing_redirect_to_is_internal() {
        let fake = FakeKratos {
            session: Arc::new(Mutex::new(Some(Ok(sample_session())))),
            ..Default::default()
        };
        let hydra = FakeHydra {
            login_request: Arc::new(Mutex::new(Some(Ok(json!({
                "challenge": "challenge-1",
                "skip": true
            }))))),
            accept_login: Arc::new(Mutex::new(Some(Ok(json!({}))))),
            ..Default::default()
        };
        let svc = service_with_hydra(fake, hydra);
        let ctx = request_context_with_cookie("ory_kratos_session=session-1");
        let req = service_request(CreateLoginFlowRequest {
            login_challenge: "challenge-1".to_string(),
            ..Default::default()
        });

        let err = svc.create_login_flow(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
    }

    #[tokio::test]
    async fn create_login_flow_proceeds_when_session_lacks_identity() {
        let fake = FakeKratos {
            session: Arc::new(Mutex::new(Some(Ok(json!({
                "id": "session-1",
                "active": true
            }))))),
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let hydra = FakeHydra {
            login_request: Arc::new(Mutex::new(Some(Ok(json!({
                "challenge": "challenge-1",
                "skip": true
            }))))),
            ..Default::default()
        };
        let svc = service_with_hydra(fake, hydra.clone());
        let ctx = request_context_with_cookie("ory_kratos_session=session-1");
        let req = service_request(CreateLoginFlowRequest {
            login_challenge: "challenge-1".to_string(),
            ..Default::default()
        });

        let resp = svc.create_login_flow(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "flow-1");
        assert!(
            hydra
                .calls()
                .iter()
                .all(|call| !call.starts_with("accept_login_request"))
        );
    }

    #[tokio::test]
    async fn create_login_flow_without_challenge_never_calls_hydra() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let hydra = FakeHydra::default();
        let svc = service_with_hydra(fake, hydra.clone());
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(CreateLoginFlowRequest::default());

        svc.create_login_flow(ctx, req).await.unwrap();
        assert!(hydra.calls().is_empty());
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
        assert_eq!(resp.body.logout_token, "pub-logout-token");
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
            id: "pub-error-1".to_string(),
            ..Default::default()
        });

        let resp = svc.get_flow_error(ctx, req).await.unwrap();
        assert_eq!(resp.body.id, "pub-error-1");
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
            "https://ui.example.com/settings?flow=privileged&foo=bar",
            &[
                "ory_kratos_session=abc; Path=/; HttpOnly",
                "csrf_token_1234=xyz; Path=/; SameSite=Lax",
            ],
        );
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie_and_csrf("session=prev", "csrf-header-value");
        let req = service_request(SubmitRecoveryTokenRequest {
            token: "recovery-token-1".to_string(),
            flow: "recovery-flow-1".to_string(),
            ..Default::default()
        });

        let resp = svc.submit_recovery_token(ctx, req).await.unwrap();
        let redirect = reqwest::Url::parse(&resp.body.redirect_to).unwrap();
        assert_eq!(redirect.host_str(), Some("ui.example.com"));
        assert_eq!(redirect.path(), "/settings");
        let pairs: std::collections::HashMap<_, _> = redirect.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("foo").map(String::as_str), Some("bar"));
        let flow = pairs.get("flow").expect("flow param should be present");
        assert_ne!(flow, "privileged");
        assert!(
            Ulid::from_string(flow).is_ok(),
            "flow param should be a public ULID, got {flow}"
        );
        assert!(!resp.body.redirect_to.contains("privileged"));
        assert_eq!(svc.resolve_flow("", flow).await.unwrap(), "privileged");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2);
        assert_eq!(
            fake.calls.lock().unwrap()[0],
            "submit_recovery_token(token=recovery-token-1, flow=recovery-flow-1, cookie=Some(\"session=prev\"), csrf_token=Some(\"csrf-header-value\"))"
        );
    }

    #[tokio::test]
    async fn submit_recovery_token_invalid_location_returns_internal() {
        let fake = FakeKratos::default();
        fake.reseed_token_submit("not-a-url", &[]);
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(SubmitRecoveryTokenRequest {
            token: "token".to_string(),
            flow: "recovery-flow-1".to_string(),
            ..Default::default()
        });

        let err = svc.submit_recovery_token(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
    }

    #[tokio::test]
    async fn submit_recovery_token_missing_location_returns_internal() {
        let fake = FakeKratos::default();
        fake.reseed_token_submit_without_location();
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(SubmitRecoveryTokenRequest {
            token: "token".to_string(),
            flow: "recovery-flow-1".to_string(),
            ..Default::default()
        });

        let err = svc.submit_recovery_token(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
    }

    #[tokio::test]
    async fn submit_recovery_token_missing_flow_returns_invalid_argument() {
        let fake = FakeKratos::default();
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(SubmitRecoveryTokenRequest {
            token: "token".to_string(),
            ..Default::default()
        });

        let err = svc.submit_recovery_token(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
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
            flow: "recovery-flow-1".to_string(),
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
            flow: "verification-flow-1".to_string(),
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
            "submit_verification_token(token=verification-token-1, flow=verification-flow-1, cookie=Some(\"session=prev\"), csrf_token=Some(\"csrf-header-value\"))"
        );
    }

    #[tokio::test]
    async fn submit_verification_token_scrubs_flow_id() {
        let fake = FakeKratos::default();
        fake.reseed_token_submit(
            "https://ui.example.com/welcome?flow=verify-me&verified=true",
            &["ory_kratos_session=abc; Path=/; HttpOnly"],
        );
        let svc = service(fake.clone());
        let ctx = request_context_with_cookie_and_csrf("session=prev", "csrf-header-value");
        let req = service_request(SubmitVerificationTokenRequest {
            token: "verification-token-1".to_string(),
            flow: "verification-flow-1".to_string(),
            ..Default::default()
        });

        let resp = svc.submit_verification_token(ctx, req).await.unwrap();
        let redirect = reqwest::Url::parse(&resp.body.redirect_to).unwrap();
        assert_eq!(redirect.host_str(), Some("ui.example.com"));
        assert_eq!(redirect.path(), "/welcome");
        let pairs: std::collections::HashMap<_, _> = redirect.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("verified").map(String::as_str), Some("true"));
        let flow = pairs.get("flow").expect("flow param should be present");
        assert_ne!(flow, "verify-me");
        assert!(
            Ulid::from_string(flow).is_ok(),
            "flow param should be a public ULID, got {flow}"
        );
        assert!(!resp.body.redirect_to.contains("verify-me"));
        assert_eq!(svc.resolve_flow("", flow).await.unwrap(), "verify-me");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            fake.calls.lock().unwrap()[0],
            "submit_verification_token(token=verification-token-1, flow=verification-flow-1, cookie=Some(\"session=prev\"), csrf_token=Some(\"csrf-header-value\"))"
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
            flow: "verification-flow-1".to_string(),
            ..Default::default()
        });

        let err = svc.submit_verification_token(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
    }

    #[tokio::test]
    async fn submit_verification_token_missing_flow_returns_invalid_argument() {
        let fake = FakeKratos::default();
        let svc = service(fake);
        let ctx = request_context_without_cookie();
        let req = service_request(SubmitVerificationTokenRequest {
            token: "token".to_string(),
            ..Default::default()
        });

        let err = svc.submit_verification_token(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
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
            flow: "verification-flow-1".to_string(),
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
    async fn flow_urls_scrub_flow_query_params() {
        let fake = FakeKratos::default();
        let svc = service(fake.clone());
        let public = svc
            .public_flow("tenant-1", "ory-settings-flow")
            .await
            .unwrap();
        fake.reseed_flow(KratosResponse {
            body: json!({
                "id": "ory-settings-flow",
                "type": "settings",
                "state": "show_form",
                "request_url": "http://kratos.example.com/self-service/settings/browser?flow=ory-settings-flow",
                "ui": {
                    "action": "http://kratos.example.com/self-service/settings?flow=ory-settings-flow",
                    "method": "POST",
                    "nodes": []
                }
            }),
            headers: http::HeaderMap::new(),
        });
        let ctx = request_context_with_tenant("tenant-1");
        let req = service_request(GetFlowRequest {
            id: public.clone(),
            ..Default::default()
        });

        let resp = svc.get_settings_flow(ctx, req).await.unwrap();
        let action = &resp.body.ui.as_option().unwrap().action;
        for value in [&resp.body.request_url, action] {
            let url = reqwest::Url::parse(value).unwrap();
            assert_eq!(url.host_str(), Some("gateway.example.com"));
            let flow = url
                .query_pairs()
                .find(|(key, _)| key == "flow")
                .map(|(_, val)| val.into_owned())
                .expect("flow param should be present");
            assert_eq!(flow, public, "expected the same public ULID in {value}");
            assert!(!value.contains("ory-settings-flow"));
        }
        assert_flow_call!(fake, "get_settings_flow(id=ory-settings-flow, cookie=None)");
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

    fn proto_struct(value: serde_json::Value) -> buffa_types::google::protobuf::Struct {
        serde_json::from_value(value).unwrap_or_default()
    }

    #[tokio::test]
    async fn submit_settings_profile_merges_traits_and_sends_base_to_kratos() {
        let fake = FakeKratos {
            session: Arc::new(Mutex::new(Some(Ok(json!({
                "id": "session-1",
                "identity": { "id": "identity-1", "traits": { "email": "alice@example.com" } }
            }))))),
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let memberships = Arc::new(StubMembershipStore::with_membership(TenantMembershipRow {
            tenant_id: "tenant-1".into(),
            identity_id: "pub-identity-1".into(),
            schema_id: "default".into(),
            schema_version: 2,
            traits: json!({"email": "alice@example.com", "name": {"first": "Alice"}}),
            state: "active".into(),
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }));
        let svc = IdentitySelfServiceImpl {
            kratos: Arc::new(fake.clone()),
            hydra: Arc::new(FakeHydra::default()),
            transient: Arc::new(default_transient_store()),
            mappings: Arc::new(default_mapping_store()),
            schemas: Arc::new(default_schema_store()),
            memberships: memberships.clone(),
            consent_enabled: true,
            kratos_public_url: "http://kratos.example.com".to_string(),
            gateway_public_url: "https://gateway.example.com".to_string(),
            kratos_default_schema_id: "default".to_string(),
        };
        let ctx = request_context_with_tenant("tenant-1");
        let req = service_request(SubmitFlowRequest {
            id: "settings-flow".to_string(),
            body: Some(proto_struct(json!({
                "method": "profile",
                "traits": { "email": "alice@example.com", "name": { "first": "Alice", "last": "Smith" } }
            })))
            .into(),
            ..Default::default()
        });

        svc.submit_settings_flow(ctx, req).await.unwrap();

        // Membership is merged with the submitted traits; email stays pinned.
        let calls = memberships.upsert_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "tenant-1");
        assert_eq!(calls[0].1, "pub-identity-1");
        assert_eq!(calls[0].2, "default");
        assert_eq!(calls[0].3, 2);
        assert_eq!(calls[0].4["email"], "alice@example.com");
        assert_eq!(
            calls[0].4["name"],
            json!({"first": "Alice", "last": "Smith"})
        );

        // Kratos only ever receives the base identity traits.
        let recorded = fake
            .calls
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.starts_with("submit_settings_flow("))
            .cloned()
            .unwrap();
        assert!(recorded.contains("\"traits\":{\"email\":\"alice@example.com\"}"));
        assert!(!recorded.contains("\"name\""));
    }

    #[tokio::test]
    async fn submit_settings_profile_rejects_email_change() {
        let fake = FakeKratos {
            session: Arc::new(Mutex::new(Some(Ok(json!({
                "id": "session-1",
                "identity": { "id": "identity-1", "traits": { "email": "alice@example.com" } }
            }))))),
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        let svc = IdentitySelfServiceImpl {
            kratos: Arc::new(fake.clone()),
            hydra: Arc::new(FakeHydra::default()),
            transient: Arc::new(default_transient_store()),
            mappings: Arc::new(default_mapping_store()),
            schemas: Arc::new(default_schema_store()),
            memberships: Arc::new(StubMembershipStore::with_membership(TenantMembershipRow {
                tenant_id: "tenant-1".into(),
                identity_id: "pub-identity-1".into(),
                schema_id: "default".into(),
                schema_version: 1,
                traits: json!({"email": "alice@example.com"}),
                state: "active".into(),
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })),
            consent_enabled: true,
            kratos_public_url: "http://kratos.example.com".to_string(),
            gateway_public_url: "https://gateway.example.com".to_string(),
            kratos_default_schema_id: "default".to_string(),
        };
        let ctx = request_context_with_tenant("tenant-1");
        let req = service_request(SubmitFlowRequest {
            id: "settings-flow".to_string(),
            body: Some(proto_struct(json!({
                "method": "profile",
                "traits": { "email": "new@example.com" }
            })))
            .into(),
            ..Default::default()
        });

        let err = svc.submit_settings_flow(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        // Kratos submit must never have been called once the email change is rejected.
        assert!(
            !fake
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.starts_with("submit_settings_flow("))
        );
    }

    #[tokio::test]
    async fn submit_settings_non_profile_passes_through_without_membership() {
        let fake = FakeKratos {
            flow: Arc::new(Mutex::new(Some(Ok(sample_flow())))),
            ..Default::default()
        };
        // No session configured: if the intercept ran, to_session would fail. A password
        // update carries no `traits`, so it must pass straight to Kratos untouched.
        let svc = service(fake.clone());
        let ctx = request_context_with_tenant("tenant-1");
        let req = service_request(SubmitFlowRequest {
            id: "settings-flow".to_string(),
            body: Some(proto_struct(
                json!({ "method": "password", "password": "hunter2" }),
            ))
            .into(),
            ..Default::default()
        });

        svc.submit_settings_flow(ctx, req).await.unwrap();
        let recorded = fake
            .calls
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.starts_with("submit_settings_flow("))
            .cloned()
            .unwrap();
        assert!(recorded.contains("\"password\":\"hunter2\""));
        assert!(
            !fake
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.starts_with("to_session("))
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
    async fn submit_login_flow_returns_redirect_and_session_cookie_on_browser_location_change() {
        let fake = FakeKratos::default();
        fake.reseed_flow_redirect(
            "https://gateway.example.com/oauth2/auth?login_verifier=v1",
            &[
                "ory_kratos_session=session-422; Path=/; HttpOnly",
                "csrf_token_422=xyz; Path=/; HttpOnly",
            ],
        );
        let svc = service(fake);
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(SubmitFlowRequest {
            id: "flow-1".to_string(),
            ..Default::default()
        });

        let resp = svc.submit_login_flow(ctx, req).await.unwrap();
        assert_eq!(
            resp.body.redirect_browser_to,
            "https://gateway.example.com/oauth2/auth?login_verifier=v1"
        );
        assert!(resp.body.id.is_empty());
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=session-422")
        );
        assert!(cookies[1].to_str().unwrap().contains("csrf_token_422=xyz"));
    }

    #[tokio::test]
    async fn submit_registration_flow_returns_redirect_and_session_cookie_on_browser_location_change()
     {
        let fake = FakeKratos::default();
        fake.reseed_flow_redirect(
            "https://gateway.example.com/oauth2/auth?login_verifier=v2",
            &["ory_kratos_session=session-reg; Path=/; HttpOnly"],
        );
        let svc = service(fake);
        let ctx = request_context_with_cookie("session=abc");
        let req = service_request(SubmitFlowRequest {
            id: "flow-1".to_string(),
            ..Default::default()
        });

        let resp = svc.submit_registration_flow(ctx, req).await.unwrap();
        assert_eq!(
            resp.body.redirect_browser_to,
            "https://gateway.example.com/oauth2/auth?login_verifier=v2"
        );
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .contains("ory_kratos_session=session-reg")
        );
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
        assert_eq!(resp.body.logout_token, "pub-logout-token");
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
                .submit_recovery_token("token", "flow", None, None)
                .await
                .is_err()
        );
        assert!(
            client
                .submit_verification_token("token", "flow", None, None)
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
