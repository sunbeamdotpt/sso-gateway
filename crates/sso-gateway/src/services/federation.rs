use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use chrono::Utc;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use gamlastan::bindings::relay_state::RelayState;
use gamlastan::bindings::{RedirectEncodeParams, redirect_encode};
use gamlastan::core::protocol::response::{
    Response as SamlResponse, ResponseRef as SamlResponseRef,
};
use gamlastan::crypto::keys::bergshamra_keys::KeysManager;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{SamlSigner, SamlVerifier};
use gamlastan::metadata::types::{
    Endpoint, EntityDescriptor, EntityRoles, IndexedEndpoint, KeyDescriptor, RoleDescriptorBase,
    SpSsoDescriptor, SsoDescriptorBase,
};
use gamlastan::profiles::sso::sp::{
    create_authn_request, process_response_with_verified_signatures,
};
use gamlastan::profiles::sso::web_browser::{AuthnRequestOptions, bindings as saml_bindings};
use gamlastan::security::SecurityConfig;
use gamlastan::xml::{SamlSerialize, parse_saml, parse_secure};
use rand::RngCore;
use sha2::Digest;
use sso_ory_client::kratos::KratosClient;
use sunbeam_g2v::error::ServiceError;
use tracing::{debug, instrument};
use ulid::Ulid;

use crate::db::{
    GamlastanReplayAdapter, IdMappingRepo, IdMappingStore, IdentitySchemaRepo, IdentitySchemaStore,
    LoginStateRepo, LoginStateStore, SamlIdentityMappingRepo, SamlIdentityMappingStore,
    SamlIdpKeyRepo, SamlIdpKeyStore, SamlProviderRepo, SamlProviderRow, SamlProviderStore,
    SamlReplayCacheTrait, SamlRequestRepo, SamlRequestStore, TenantConnectionRepo,
    TenantConnectionStore, TenantDomainRepo, TenantDomainStore,
};
use crate::hrd::Hrd;
use crate::identity_provisioner::{
    IdentityProvisioner, KratosIdentityProvisioner, ProvisionedIdentity,
};
use crate::middleware::TenantId;
use crate::proto::iam::v1::{
    AcceptSamlAssertionRequest, DiscoverLoginMethodRequest, DiscoverLoginMethodResponse,
    FederationService, GetJSONWebKeysRequest, GetOpenIDConfigurationRequest,
    InitiateOAuth2LoginRequest, InitiateOAuth2LoginResponse, InitiateOidcLoginRequest,
    InitiateOidcLoginResponse, InitiateSamlLoginRequest, JSONWebKey, JSONWebKeySet, OAuth2Redirect,
    OidcRedirect, OpenIDConfiguration, SamlLoginResponse, SamlRedirect, Session,
};
use crate::services::handlers::callback::SamlAcsService;
use crate::upstream_oauth::validate_upstream_url;

#[allow(dead_code)]
const BACKEND_KRATOS: &str = "kratos";

#[async_trait::async_trait]
#[allow(dead_code)]
trait FederationKratos: Send + Sync + 'static {
    async fn create_identity(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, sso_ory_client::error::OryClientError>;
}

#[async_trait::async_trait]
impl FederationKratos for KratosClient {
    async fn create_identity(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, sso_ory_client::error::OryClientError> {
        self.create_identity(payload).await
    }
}

#[async_trait::async_trait]
trait FederationHydra: Send + Sync + 'static {
    async fn fetch_discovery(&self, url: &str) -> Result<serde_json::Value, ServiceError>;
    async fn fetch_jwks(&self, url: &str) -> Result<serde_json::Value, ServiceError>;
}

#[async_trait::async_trait]
impl FederationHydra for reqwest::Client {
    async fn fetch_discovery(&self, url: &str) -> Result<serde_json::Value, ServiceError> {
        self.get(url)
            .send()
            .await
            .map_err(|e| ServiceError::Unavailable(format!("hydra discovery: {e}")))?
            .json()
            .await
            .map_err(|e| ServiceError::Serialization(format!("hydra discovery json: {e}")))
    }

    async fn fetch_jwks(&self, url: &str) -> Result<serde_json::Value, ServiceError> {
        self.get(url)
            .send()
            .await
            .map_err(|e| ServiceError::Unavailable(format!("hydra jwks: {e}")))?
            .json()
            .await
            .map_err(|e| ServiceError::Serialization(format!("hydra jwks json: {e}")))
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct FederationServiceImpl {
    kratos: Arc<dyn FederationKratos>,
    pub(crate) providers: Arc<dyn SamlProviderStore>,
    requests: Arc<dyn SamlRequestStore>,
    mappings: Arc<dyn IdMappingStore>,
    federation_mappings: Arc<dyn SamlIdentityMappingStore>,
    schemas: Arc<dyn IdentitySchemaStore>,
    #[allow(dead_code)]
    idp_keys: Arc<dyn SamlIdpKeyStore>,
    #[allow(dead_code)]
    connections: Arc<dyn TenantConnectionStore>,
    #[allow(dead_code)]
    domains: Arc<dyn TenantDomainStore>,
    login_state: Arc<dyn LoginStateStore>,
    identity_provisioner: Arc<dyn IdentityProvisioner>,
    hrd: Hrd,
    hydra_public_url: String,
    public_base_url: String,
    http: Arc<dyn FederationHydra>,
    saml_signer: Option<Arc<SamlSigner>>,
    sp_certificate_pem: Option<String>,
    request_ttl: Duration,
    require_signed_assertions: bool,
    require_signed_responses: bool,
    replay_cache: Arc<dyn SamlReplayCacheTrait>,
}

impl FederationServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kratos: Arc<KratosClient>,
        providers: SamlProviderRepo,
        requests: SamlRequestRepo,
        mappings: IdMappingRepo,
        federation_mappings: SamlIdentityMappingRepo,
        schemas: IdentitySchemaRepo,
        idp_keys: SamlIdpKeyRepo,
        connections: TenantConnectionRepo,
        domains: TenantDomainRepo,
        login_state: LoginStateRepo,
        hydra_public_url: String,
        public_base_url: String,
        saml_signer: Option<Arc<SamlSigner>>,
        sp_certificate_pem: Option<String>,
        request_ttl: Duration,
        require_signed_assertions: bool,
        require_signed_responses: bool,
        replay_cache: Arc<dyn SamlReplayCacheTrait>,
    ) -> Self {
        let providers: Arc<dyn SamlProviderStore> = Arc::new(providers);
        let connections: Arc<dyn TenantConnectionStore> = Arc::new(connections);
        let domains: Arc<dyn TenantDomainStore> = Arc::new(domains);
        let mappings: Arc<dyn IdMappingStore> = Arc::new(mappings);
        let schemas: Arc<dyn IdentitySchemaStore> = Arc::new(schemas);
        let identity_provisioner: Arc<dyn IdentityProvisioner> = Arc::new(
            KratosIdentityProvisioner::new(kratos.clone(), mappings.clone(), schemas.clone())
                .with_saml_mappings(
                    Arc::new(federation_mappings.clone()) as Arc<dyn SamlIdentityMappingStore>
                ),
        );
        let hrd = Hrd::new(
            connections.clone(),
            domains.clone(),
            providers.clone(),
            public_base_url.clone(),
        );
        Self {
            kratos: kratos as Arc<dyn FederationKratos>,
            providers,
            requests: Arc::new(requests) as Arc<dyn SamlRequestStore>,
            mappings,
            federation_mappings: Arc::new(federation_mappings) as Arc<dyn SamlIdentityMappingStore>,
            schemas,
            idp_keys: Arc::new(idp_keys) as Arc<dyn SamlIdpKeyStore>,
            connections,
            domains,
            login_state: Arc::new(login_state) as Arc<dyn LoginStateStore>,
            identity_provisioner,
            hrd,
            hydra_public_url,
            public_base_url,
            http: Arc::new(
                reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap_or_else(|_| reqwest::Client::new()),
            ) as Arc<dyn FederationHydra>,
            saml_signer,
            sp_certificate_pem,
            request_ttl,
            require_signed_assertions,
            require_signed_responses,
            replay_cache,
        }
    }
}

#[allow(refining_impl_trait)]
impl FederationService for FederationServiceImpl {
    #[instrument(skip(self, request))]
    async fn discover_login_method(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, DiscoverLoginMethodRequest>,
    ) -> ServiceResult<DiscoverLoginMethodResponse> {
        let req = request.to_owned_message();
        let result = self
            .hrd
            .discover(&req.email, &req.return_to)
            .await
            .map_err(ServiceError::from)?;
        let response = match result {
            crate::hrd::DiscoveryResult::Oidc(crate::hrd::OidcRedirect { authorization_url }) => {
                DiscoverLoginMethodResponse {
                    method: Some(
                        crate::proto::iam::v1::discover_login_method_response::Method::Oidc(
                            Box::new(OidcRedirect {
                                authorization_url,
                                state: String::new(),
                                __buffa_unknown_fields: Default::default(),
                            }),
                        ),
                    ),
                    __buffa_unknown_fields: Default::default(),
                }
            }
            crate::hrd::DiscoveryResult::OAuth2(crate::hrd::OAuth2Redirect {
                authorization_url,
            }) => DiscoverLoginMethodResponse {
                method: Some(
                    crate::proto::iam::v1::discover_login_method_response::Method::Oauth2(
                        Box::new(OAuth2Redirect {
                            authorization_url,
                            state: String::new(),
                            __buffa_unknown_fields: Default::default(),
                        }),
                    ),
                ),
                __buffa_unknown_fields: Default::default(),
            },
            crate::hrd::DiscoveryResult::Saml(crate::hrd::SamlRedirect {
                sso_url,
                saml_request,
                relay_state,
            }) => DiscoverLoginMethodResponse {
                method: Some(
                    crate::proto::iam::v1::discover_login_method_response::Method::Saml(Box::new(
                        SamlRedirect {
                            sso_url,
                            saml_request,
                            relay_state,
                            __buffa_unknown_fields: Default::default(),
                        },
                    )),
                ),
                __buffa_unknown_fields: Default::default(),
            },
            crate::hrd::DiscoveryResult::SelectTenant(crate::hrd::TenantSelectionRedirect {
                redirect_url,
            }) => DiscoverLoginMethodResponse {
                method: Some(
                    crate::proto::iam::v1::discover_login_method_response::Method::SelectTenant(
                        Box::new(crate::proto::iam::v1::SelectTenantRedirect {
                            redirect_url,
                            __buffa_unknown_fields: Default::default(),
                        }),
                    ),
                ),
                __buffa_unknown_fields: Default::default(),
            },
        };
        Ok(Response::new(response))
    }

    #[instrument(skip(self, request))]
    async fn initiate_oidc_login(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, InitiateOidcLoginRequest>,
    ) -> ServiceResult<InitiateOidcLoginResponse> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let connection = self
            .connections
            .get_by_id(&tenant_id, &req.connection_id)
            .await
            .map_err(ServiceError::from)?;
        if connection.connection_type != crate::db::ConnectionType::Oidc {
            return Err(ServiceError::InvalidArgument(
                "connection is not an OIDC connection".into(),
            )
            .into());
        }
        let code_verifier = generate_code_verifier();
        let nonce = generate_nonce();
        let state = self
            .login_state
            .create(
                &tenant_id,
                &req.connection_id,
                "oidc",
                &req.return_to,
                Some(code_verifier.clone()),
                Some(nonce.clone()),
                self.request_ttl,
            )
            .await
            .map_err(ServiceError::from)?;
        let authorization_url = build_oidc_authorization_url(
            &connection.config,
            &format!(
                "{}/callbacks/oidc",
                self.public_base_url.trim_end_matches('/')
            ),
            &state.state_token,
            &code_verifier,
            &nonce,
        )?;
        Ok(Response::new(InitiateOidcLoginResponse {
            authorization_url,
            state: state.state_token,
            __buffa_unknown_fields: Default::default(),
        }))
    }

    #[instrument(skip(self, request))]
    async fn initiate_o_auth2_login(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, InitiateOAuth2LoginRequest>,
    ) -> ServiceResult<InitiateOAuth2LoginResponse> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let connection = self
            .connections
            .get_by_id(&tenant_id, &req.connection_id)
            .await
            .map_err(ServiceError::from)?;
        if connection.connection_type != crate::db::ConnectionType::OAuth2 {
            return Err(ServiceError::InvalidArgument(
                "connection is not an OAuth2 connection".into(),
            )
            .into());
        }
        let code_verifier = generate_code_verifier();
        let state = self
            .login_state
            .create(
                &tenant_id,
                &req.connection_id,
                "oauth2",
                &req.return_to,
                Some(code_verifier.clone()),
                None,
                self.request_ttl,
            )
            .await
            .map_err(ServiceError::from)?;
        let authorization_url = build_oauth2_authorization_url(
            &connection.config,
            &format!(
                "{}/callbacks/oauth2",
                self.public_base_url.trim_end_matches('/')
            ),
            &state.state_token,
            &code_verifier,
        )?;
        Ok(Response::new(InitiateOAuth2LoginResponse {
            authorization_url,
            state: state.state_token,
            __buffa_unknown_fields: Default::default(),
        }))
    }

    #[instrument(skip(self))]
    async fn get_open_id_configuration(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetOpenIDConfigurationRequest>,
    ) -> ServiceResult<OpenIDConfiguration> {
        let discovery_url = format!("{}/.well-known/openid-configuration", self.hydra_public_url);
        debug!(%discovery_url, "fetching hydra openid configuration");

        let value: serde_json::Value = self.http.fetch_discovery(&discovery_url).await?;

        Ok(Response::new(OpenIDConfiguration {
            issuer: json_str(&value, "issuer"),
            authorization_endpoint: json_str(&value, "authorization_endpoint"),
            token_endpoint: json_str(&value, "token_endpoint"),
            userinfo_endpoint: json_str(&value, "userinfo_endpoint"),
            jwks_uri: json_str(&value, "jwks_uri"),
            response_types_supported: json_str_array(&value, "response_types_supported"),
            grant_types_supported: json_str_array(&value, "grant_types_supported"),
            subject_types_supported: json_str_array(&value, "subject_types_supported"),
            id_token_signing_alg_values_supported: json_str_array(
                &value,
                "id_token_signing_alg_values_supported",
            ),
            scopes_supported: json_str_array(&value, "scopes_supported"),
            ..Default::default()
        }))
    }

    #[instrument(skip(self))]
    async fn get_json_web_keys(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetJSONWebKeysRequest>,
    ) -> ServiceResult<JSONWebKeySet> {
        let jwks_url = format!("{}/oauth2/jwks.json", self.hydra_public_url);
        debug!(%jwks_url, "fetching hydra jwks");

        let value: serde_json::Value = self.http.fetch_jwks(&jwks_url).await?;

        let keys = value
            .get("keys")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let keys = keys.into_iter().map(json_web_key_to_proto).collect();
        Ok(Response::new(JSONWebKeySet {
            keys,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn initiate_saml_login(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, InitiateSamlLoginRequest>,
    ) -> ServiceResult<SamlLoginResponse> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();

        let provider = self.providers.get(&tenant_id, &req.provider_id).await?;

        if provider.authn_requests_signed && self.saml_signer.is_none() {
            return Err(ServiceError::Configuration(
                "provider requires signed AuthnRequests but no SAML signing key is configured"
                    .into(),
            )
            .into());
        }

        let options = AuthnRequestOptions {
            sp_entity_id: provider.sp_entity_id.clone(),
            acs_url: Some(provider.acs_url.clone()),
            protocol_binding: Some(saml_bindings::HTTP_POST.to_string()),
            destination: Some(provider.idp_sso_url.clone()),
            name_id_format: provider.name_id_format.clone(),
            allow_create: true,
            ..Default::default()
        };

        let authn_request = create_authn_request(&options)
            .map_err(|e| ServiceError::InvalidArgument(format!("saml authn request: {e}")))?;
        let request_id = authn_request.base.id.clone();

        let saml_xml = authn_request
            .to_xml_string()
            .map_err(|e| ServiceError::Internal(format!("saml serialize: {e}")))?;

        let relay_state = RelayState::new(&req.relay_state)
            .map_err(|e| ServiceError::InvalidArgument(format!("relay state: {e}")))?;

        const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        let signer = self.saml_signer.as_ref().map(|s| (s.as_ref(), RSA_SHA256));

        let redirect_url = redirect_encode(&RedirectEncodeParams {
            saml_xml: saml_xml.as_bytes(),
            is_request: true,
            destination: &provider.idp_sso_url,
            relay_state: Some(&relay_state),
            signer,
        })
        .map_err(|e| ServiceError::Internal(format!("redirect encode: {e}")))?;

        self.requests
            .create(&tenant_id, &request_id, &provider.id, &req.relay_state)
            .await?;

        Ok(Response::new(SamlLoginResponse {
            redirect_url,
            request_id,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn accept_saml_assertion(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AcceptSamlAssertionRequest>,
    ) -> ServiceResult<Session> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();

        let request_id = parse_saml_request_id(&req.encoded_assertion)?;

        let pending = self.requests.get(&tenant_id, &request_id).await?;
        let provider = self.providers.get(&tenant_id, &pending.provider_id).await?;

        if req.relay_state != pending.relay_state {
            return Err(ServiceError::InvalidArgument("relay state mismatch".into()).into());
        }

        let request_age = time::OffsetDateTime::now_utc() - pending.created_at;
        if request_age.whole_seconds() > self.request_ttl.as_secs() as i64 {
            return Err(ServiceError::InvalidArgument("saml request expired".into()).into());
        }

        let identity = self
            .process_saml_assertion(&tenant_id, &provider, &req.encoded_assertion, &request_id)
            .await?;

        let session_id = Ulid::new().to_string();
        Ok(Response::new(Session {
            id: session_id,
            identity_id: identity.public_id,
            tenant_id,
            active: true,
            ..Default::default()
        }))
    }
}

impl FederationServiceImpl {
    /// Provision (or link) a Kratos identity from a validated SAML assertion.
    async fn provision_saml_identity(
        &self,
        tenant_id: &str,
        provider: &SamlProviderRow,
        name_id: &str,
        email: &str,
    ) -> Result<ProvisionedIdentity, ServiceError> {
        // SAML identity providers are treated as trusted for the purposes of
        // email linking, but per-provider saml_identity_mappings are still
        // preferred when present.
        self.identity_provisioner
            .provision_saml(
                tenant_id,
                &provider.id,
                &provider.schema_id,
                name_id,
                email,
                false,
                true,
            )
            .await
            .map_err(ServiceError::from)
    }

    /// Validate a SAML assertion and provision (or link) the corresponding
    /// identity. Used by both the Connect-RPC `AcceptSamlAssertion` method and
    /// the public HTTP ACS callback.
    pub async fn process_saml_assertion(
        &self,
        tenant_id: &str,
        provider: &SamlProviderRow,
        encoded_assertion: &str,
        request_id: &str,
    ) -> Result<ProvisionedIdentity, ServiceError> {
        // Fail closed: if the gateway is configured to require signed assertions
        // or responses, the provider must have a certificate before we parse
        // anything.
        if provider.idp_certificate_pem.is_none() {
            if self.require_signed_assertions {
                return Err(ServiceError::Configuration(
                    "provider requires signed assertions but no IdP certificate is configured"
                        .into(),
                ));
            }
            if self.require_signed_responses {
                return Err(ServiceError::Configuration(
                    "provider requires signed responses but no IdP certificate is configured"
                        .into(),
                ));
            }
        }

        let saml_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded_assertion,
        )
        .map_err(|e| ServiceError::InvalidArgument(format!("base64: {e}")))?;
        let saml_xml = String::from_utf8(saml_bytes)
            .map_err(|e| ServiceError::InvalidArgument(format!("utf8: {e}")))?;

        let doc = parse_secure(&saml_xml)
            .map_err(|e| ServiceError::InvalidArgument(format!("saml parse: {e}")))?;
        let response: SamlResponse = parse_saml::<SamlResponseRef>(&doc)
            .map_err(|e| ServiceError::InvalidArgument(format!("saml response: {e}")))?
            .to_owned();

        let verified_signed_ids =
            verify_saml_signature(&saml_xml, provider.idp_certificate_pem.as_deref())
                .map_err(|e| ServiceError::InvalidArgument(format!("saml signature: {e}")))?;

        let mut security_config = SecurityConfig::new();
        let has_idp_cert = provider.idp_certificate_pem.is_some();
        security_config.require_signed_assertions = has_idp_cert && self.require_signed_assertions;
        security_config.require_signed_responses = has_idp_cert && self.require_signed_responses;
        security_config.require_encrypted_assertions = false;

        let signed_ids_owned: Vec<String> = verified_signed_ids.to_vec();
        let replay_adapter = GamlastanReplayAdapter::new(self.replay_cache.clone());
        let response = response.clone();
        let security_config = security_config.clone();
        let sp_entity_id = provider.sp_entity_id.clone();
        let acs_url = provider.acs_url.clone();
        let request_id_owned = request_id.to_string();
        let idp_entity_id = provider.idp_entity_id.clone();
        let now = Utc::now();

        let result = tokio::task::spawn_blocking(move || {
            let signed_ids: Vec<&str> = signed_ids_owned.iter().map(|s| s.as_str()).collect();
            process_response_with_verified_signatures(
                &response,
                &security_config,
                Some(&replay_adapter),
                &sp_entity_id,
                &acs_url,
                Some(&request_id_owned),
                &idp_entity_id,
                &signed_ids,
                now,
            )
        })
        .await
        .map_err(|e| ServiceError::Internal(format!("saml processing task failed: {e}")))?
        .map_err(|e| ServiceError::InvalidArgument(format!("saml validation: {e}")))?;

        self.requests.delete(tenant_id, request_id).await.ok();

        // Validate the identity schema registered for this tenant.
        let _schema = self
            .schemas
            .get_by_schema_id(tenant_id, &provider.schema_id)
            .await?;

        let name_id = result.name_id.clone();
        let email = result
            .attributes
            .iter()
            .find(|a| a.name == "email")
            .and_then(|a| a.values.first())
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| name_id.clone());

        self.provision_saml_identity(tenant_id, provider, &name_id, &email)
            .await
    }

    /// Generate SAML 2.0 SP metadata XML for a configured provider.
    pub fn generate_sp_metadata(&self, provider: &SamlProviderRow) -> Result<String, ServiceError> {
        let mut base =
            RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]);

        if let Some(cert_pem) = &self.sp_certificate_pem
            && let Some(key_info) = key_info_from_certificate_pem(cert_pem)
        {
            base.key_descriptors.push(KeyDescriptor::signing(key_info));
        }

        let mut name_id_formats = Vec::new();
        if let Some(format) = &provider.name_id_format {
            name_id_formats.push(format.clone());
        }

        let acs_url = resolve_acs_url(&self.public_base_url, &provider.acs_url);
        let acs_endpoint =
            IndexedEndpoint::new_default(Endpoint::new(saml_bindings::HTTP_POST, acs_url), 0);

        let authn_requests_signed = provider.authn_requests_signed && self.saml_signer.is_some();

        let sp = SpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base,
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats,
            },
            authn_requests_signed: Some(authn_requests_signed),
            want_assertions_signed: Some(self.require_signed_assertions),
            assertion_consumer_services: vec![acs_endpoint],
            attribute_consuming_services: vec![],
        };

        let entity = EntityDescriptor {
            entity_id: provider.sp_entity_id.clone(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![],
                sp_sso: vec![sp],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        };

        entity
            .to_xml_string()
            .map_err(|e| ServiceError::Internal(format!("saml metadata serialize: {e}")))
    }
}

#[async_trait::async_trait]
impl SamlAcsService for FederationServiceImpl {
    async fn process_saml_assertion_http(
        &self,
        encoded_assertion: &str,
        relay_state: &str,
    ) -> Result<ProvisionedIdentity, ServiceError> {
        let request_id = parse_saml_request_id(encoded_assertion)?;

        let pending = self
            .requests
            .get_by_request_id(&request_id)
            .await
            .map_err(ServiceError::from)?;
        let provider = self
            .providers
            .get(&pending.tenant_id, &pending.provider_id)
            .await?;

        if relay_state != pending.relay_state {
            return Err(ServiceError::InvalidArgument("relay state mismatch".into()));
        }

        let request_age = time::OffsetDateTime::now_utc() - pending.created_at;
        if request_age.whole_seconds() > self.request_ttl.as_secs() as i64 {
            return Err(ServiceError::InvalidArgument("saml request expired".into()));
        }

        self.process_saml_assertion(
            &pending.tenant_id,
            &provider,
            encoded_assertion,
            &request_id,
        )
        .await
    }
}

fn resolve_acs_url(public_base_url: &str, provider_acs_url: &str) -> String {
    if provider_acs_url.starts_with('/') {
        format!(
            "{}{}",
            public_base_url.trim_end_matches('/'),
            provider_acs_url
        )
    } else {
        provider_acs_url.to_string()
    }
}

fn key_info_from_certificate_pem(cert_pem: &str) -> Option<String> {
    let base64 = cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    if base64.is_empty() {
        return None;
    }
    Some(format!(
        r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{base64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#
    ))
}

fn verify_saml_signature(
    saml_xml: &str,
    idp_certificate_pem: Option<&str>,
) -> Result<Vec<String>, gamlastan::crypto::error::CryptoError> {
    let Some(cert_pem) = idp_certificate_pem else {
        return Ok(Vec::new());
    };

    let mut keys_manager = KeysManager::new();
    let mut loaded = false;
    for cert_block in split_certificate_pem_blocks(cert_pem) {
        match loader::load_x509_cert_pem(cert_block.as_bytes()) {
            Ok(cert_key) => {
                keys_manager.add_key(cert_key);
                loaded = true;
            }
            Err(_) => continue,
        }
    }

    if !loaded {
        return Err(gamlastan::crypto::error::CryptoError::KeyNotFound(
            "no loadable IdP certificates".to_string(),
        ));
    }

    let verifier = SamlVerifier::new(keys_manager);
    match verifier.verify_enveloped(saml_xml)? {
        gamlastan::crypto::VerifyResult::Valid { references, .. } => {
            let ids: Vec<String> = references
                .into_iter()
                .filter_map(|r| r.uri.strip_prefix('#').map(|s| s.to_string()))
                .collect();
            Ok(ids)
        }
        gamlastan::crypto::VerifyResult::Invalid { reason } => Err(
            gamlastan::crypto::error::CryptoError::VerificationFailed(reason),
        ),
    }
}

fn split_certificate_pem_blocks(pem: &str) -> Vec<&str> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut blocks = Vec::new();
    let mut cursor = 0;
    while let Some(start) = pem[cursor..].find(BEGIN) {
        let abs_start = cursor + start;
        if let Some(end) = pem[abs_start..].find(END) {
            let abs_end = abs_start + end + END.len();
            blocks.push(&pem[abs_start..abs_end]);
            cursor = abs_end;
        } else {
            break;
        }
    }
    blocks
}

fn build_oidc_authorization_url(
    config: &serde_json::Value,
    redirect_uri: &str,
    state: &str,
    code_verifier: &str,
    nonce: &str,
) -> Result<String, ServiceError> {
    let authorization_endpoint = config["authorization_endpoint"]
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| {
            config["issuer"]
                .as_str()
                .map(|issuer| format!("{}/oauth2/authorize", issuer.trim_end_matches('/')))
        })
        .ok_or_else(|| {
            ServiceError::InvalidArgument("missing authorization_endpoint or issuer".into())
        })?;
    let client_id = config["client_id"]
        .as_str()
        .ok_or_else(|| ServiceError::InvalidArgument("missing client_id".into()))?;
    let scope = config["scopes"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ServiceError::InvalidArgument("missing scopes".into()))?;

    validate_oauth_url("authorization_endpoint", &authorization_endpoint)?;
    if let Some(issuer) = config["issuer"].as_str() {
        validate_oauth_url("issuer", issuer)?;
    }
    if let Some(token_url) = config["token_url"].as_str() {
        validate_oauth_url("token_url", token_url)?;
    }
    if let Some(userinfo_url) = config["userinfo_url"].as_str() {
        validate_oauth_url("userinfo_url", userinfo_url)?;
    }

    let code_challenge = compute_code_challenge(code_verifier);

    Ok(format!(
        "{}?client_id={}&response_type=code&scope={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256&nonce={}",
        authorization_endpoint.trim_end_matches('/'),
        urlencoding::encode(client_id),
        urlencoding::encode(&scope),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state),
        urlencoding::encode(&code_challenge),
        urlencoding::encode(nonce),
    ))
}

fn build_oauth2_authorization_url(
    config: &serde_json::Value,
    redirect_uri: &str,
    state: &str,
    code_verifier: &str,
) -> Result<String, ServiceError> {
    let authorization_url = config["authorization_url"]
        .as_str()
        .ok_or_else(|| ServiceError::InvalidArgument("missing authorization_url".into()))?;
    let client_id = config["client_id"]
        .as_str()
        .ok_or_else(|| ServiceError::InvalidArgument("missing client_id".into()))?;
    let scope = config["scopes"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ServiceError::InvalidArgument("missing scopes".into()))?;

    validate_oauth_url("authorization_url", authorization_url)?;
    if let Some(token_url) = config["token_url"].as_str() {
        validate_oauth_url("token_url", token_url)?;
    }
    if let Some(userinfo_url) = config["userinfo_url"].as_str() {
        validate_oauth_url("userinfo_url", userinfo_url)?;
    }

    let code_challenge = compute_code_challenge(code_verifier);

    Ok(format!(
        "{}?client_id={}&response_type=code&scope={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256",
        authorization_url,
        urlencoding::encode(client_id),
        urlencoding::encode(&scope),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state),
        urlencoding::encode(&code_challenge),
    ))
}

fn parse_saml_request_id(encoded_assertion: &str) -> Result<String, ServiceError> {
    let saml_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded_assertion,
    )
    .map_err(|e| ServiceError::InvalidArgument(format!("base64: {e}")))?;
    let saml_xml = String::from_utf8(saml_bytes)
        .map_err(|e| ServiceError::InvalidArgument(format!("utf8: {e}")))?;

    let doc = parse_secure(&saml_xml)
        .map_err(|e| ServiceError::InvalidArgument(format!("saml parse: {e}")))?;
    let response: SamlResponse = parse_saml::<SamlResponseRef>(&doc)
        .map_err(|e| ServiceError::InvalidArgument(format!("saml response: {e}")))?
        .to_owned();

    response
        .base
        .in_response_to
        .ok_or_else(|| ServiceError::InvalidArgument("unsolicited saml response".into()))
}

fn require_tenant(ctx: &RequestContext) -> Result<String, ServiceError> {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .ok_or_else(|| ServiceError::Unauthenticated("missing tenant".into()))
}

fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn compute_code_challenge(verifier: &str) -> String {
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn validate_oauth_url(name: &str, url: &str) -> Result<(), ServiceError> {
    validate_upstream_url(url).map_err(|e| {
        ServiceError::InvalidArgument(format!("{name} is not a valid upstream URL: {e}"))
    })
}

#[allow(dead_code)]
fn map_ory_error(err: sso_ory_client::error::OryClientError) -> ServiceError {
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
        OryClientError::Http(e) => ServiceError::Unavailable(e.to_string()),
        OryClientError::Serialization(e) => ServiceError::Serialization(e.to_string()),
        OryClientError::Url(e) => ServiceError::Configuration(e.to_string()),
        OryClientError::InvalidResponse(msg) => ServiceError::Internal(msg),
        OryClientError::MissingTenant => {
            ServiceError::Unauthenticated("missing tenant context".into())
        }
        OryClientError::Redirect { .. } => ServiceError::Internal("unexpected redirect".into()),
    }
}

fn json_str(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn json_str_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn json_web_key_to_proto(value: serde_json::Value) -> JSONWebKey {
    let str_field = |key: &str| {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    JSONWebKey {
        kty: str_field("kty"),
        r#use: str_field("use"),
        kid: str_field("kid"),
        alg: str_field("alg"),
        n: str_field("n"),
        e: str_field("e"),
        x: str_field("x"),
        y: str_field("y"),
        crv: str_field("crv"),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
    use gamlastan::core::assertion::name_id::NameId;
    use gamlastan::core::constants;
    use gamlastan::profiles::sso::idp::create_response;
    use gamlastan::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
    use gamlastan::security::InMemoryReplayCache;
    use gamlastan::xml::SamlSerialize;
    use serde_json::json;
    use sso_ory_client::error::OryClientError;
    use sso_ory_client::kratos::KratosClient;
    use std::sync::Mutex;

    use crate::db::{
        DbError, IdMappingRow, IdentitySchemaRow, SamlIdentityMappingRow, SamlIdpKeyRow,
        SamlRequestRow,
    };
    use base64::Engine;
    use buffa::Message;
    use buffa::view::MessageView;

    fn decode_request<'a, Req: buffa::view::HasMessageView>(
        bytes: &'a buffa::bytes::Bytes,
    ) -> Result<Req::View<'a>, ServiceError> {
        Req::View::decode_view(bytes)
            .map_err(|e| ServiceError::Internal(format!("failed to decode request: {e}")))
    }

    macro_rules! svc_req {
        ($id:ident, $req:expr, $ty:ty) => {
            let bytes = buffa::bytes::Bytes::from($req.encode_to_vec());
            let view = decode_request::<$ty>(&bytes).expect("decode request");
            let $id = ServiceRequest::<$ty>::from_parts(&view, &bytes);
        };
    }

    fn tenant_context(tenant_id: &str) -> RequestContext {
        let mut ctx = RequestContext::new(http::HeaderMap::new());
        ctx.extensions_mut().insert(TenantId(tenant_id.into()));
        ctx
    }

    fn test_provider() -> SamlProviderRow {
        SamlProviderRow {
            id: "provider-1".into(),
            tenant_id: "tenant-1".into(),
            name: "Provider".into(),
            idp_entity_id: "https://idp.example.com".into(),
            idp_sso_url: "https://idp.example.com/sso".into(),
            idp_certificate_pem: None,
            sp_entity_id: "https://sp.example.com".into(),
            acs_url: "https://sp.example.com/acs".into(),
            name_id_format: Some(constants::NAMEID_EMAIL.to_string()),
            schema_id: "default".into(),
            authn_requests_signed: false,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn test_schema() -> IdentitySchemaRow {
        IdentitySchemaRow {
            id: "schema-1".into(),
            tenant_id: "tenant-1".into(),
            schema_id: "default".into(),
            schema_json: json!({}),
            version: 1,
            is_default: true,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn encode_saml_response(response: &SamlResponse) -> String {
        let xml = response.to_xml_string().expect("serialize response");
        base64::engine::general_purpose::STANDARD.encode(xml)
    }

    #[derive(Clone, Default)]
    struct StubKratos {
        create_identity_result: Arc<Mutex<Option<Result<serde_json::Value, OryClientError>>>>,
    }

    #[async_trait::async_trait]
    impl FederationKratos for StubKratos {
        async fn create_identity(
            &self,
            _payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            self.create_identity_result
                .lock()
                .unwrap()
                .take()
                .expect("kratos stub not configured")
        }
    }

    #[derive(Clone, Default)]
    struct StubHydra {
        discovery_result: Arc<Mutex<Option<Result<serde_json::Value, ServiceError>>>>,
        jwks_result: Arc<Mutex<Option<Result<serde_json::Value, ServiceError>>>>,
    }

    #[async_trait::async_trait]
    impl FederationHydra for StubHydra {
        async fn fetch_discovery(&self, _url: &str) -> Result<serde_json::Value, ServiceError> {
            self.discovery_result
                .lock()
                .unwrap()
                .take()
                .expect("hydra discovery stub not configured")
        }

        async fn fetch_jwks(&self, _url: &str) -> Result<serde_json::Value, ServiceError> {
            self.jwks_result
                .lock()
                .unwrap()
                .take()
                .expect("hydra jwks stub not configured")
        }
    }

    #[derive(Clone, Default)]
    struct StubProviderStore {
        provider: Arc<Mutex<Option<Result<SamlProviderRow, DbError>>>>,
    }

    #[async_trait::async_trait]
    impl SamlProviderStore for StubProviderStore {
        #[allow(clippy::too_many_arguments)]
        async fn create(
            &self,
            _tenant_id: &str,
            _name: &str,
            _idp_entity_id: &str,
            _idp_sso_url: &str,
            _idp_certificate_pem: Option<&str>,
            _sp_entity_id: &str,
            _acs_url: &str,
            _name_id_format: Option<&str>,
            _schema_id: &str,
            _authn_requests_signed: bool,
        ) -> Result<SamlProviderRow, DbError> {
            unimplemented!()
        }

        async fn get(&self, _tenant_id: &str, _id: &str) -> Result<SamlProviderRow, DbError> {
            self.provider
                .lock()
                .unwrap()
                .take()
                .expect("provider stub not configured")
        }

        async fn get_by_id(&self, _id: &str) -> Result<SamlProviderRow, DbError> {
            self.provider
                .lock()
                .unwrap()
                .take()
                .expect("provider stub not configured")
        }
    }

    #[derive(Clone, Default)]
    struct StubRequestStore {
        create_result: Arc<Mutex<Option<Result<SamlRequestRow, DbError>>>>,
        get_result: Arc<Mutex<Option<Result<SamlRequestRow, DbError>>>>,
        delete_ok: Arc<Mutex<bool>>,
    }

    #[async_trait::async_trait]
    impl SamlRequestStore for StubRequestStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _request_id: &str,
            _provider_id: &str,
            _relay_state: &str,
        ) -> Result<SamlRequestRow, DbError> {
            self.create_result
                .lock()
                .unwrap()
                .take()
                .expect("request create stub not configured")
        }

        async fn get(
            &self,
            _tenant_id: &str,
            _request_id: &str,
        ) -> Result<SamlRequestRow, DbError> {
            self.get_result
                .lock()
                .unwrap()
                .take()
                .expect("request get stub not configured")
        }

        async fn get_by_request_id(&self, _request_id: &str) -> Result<SamlRequestRow, DbError> {
            self.get_result
                .lock()
                .unwrap()
                .take()
                .expect("request get stub not configured")
        }

        async fn delete(&self, _tenant_id: &str, _request_id: &str) -> Result<(), DbError> {
            if *self.delete_ok.lock().unwrap() {
                Ok(())
            } else {
                Err(DbError::SamlRequestNotFound)
            }
        }

        async fn create_inbound(
            &self,
            _tenant_id: &str,
            _provider_id: &str,
            _request_id: &str,
            _ttl: std::time::Duration,
        ) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct StubMappingStore {
        create_result: Arc<Mutex<Option<Result<IdMappingRow, DbError>>>>,
    }

    #[async_trait::async_trait]
    impl IdMappingStore for StubMappingStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
            _ory_global_id: &str,
        ) -> Result<IdMappingRow, DbError> {
            self.create_result
                .lock()
                .unwrap()
                .take()
                .expect("mapping create stub not configured")
        }

        async fn get_ory_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<String, DbError> {
            unimplemented!()
        }

        async fn get_public_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, DbError> {
            unimplemented!()
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn list_public_ids(
            &self,
            _tenant_id: &str,
            _backend: &str,
        ) -> Result<Vec<String>, DbError> {
            unimplemented!()
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, DbError> {
            unimplemented!()
        }
    }

    #[derive(Clone, Default)]
    struct StubFederationMappingStore {
        get_by_name_id_result: Arc<Mutex<Option<Result<SamlIdentityMappingRow, DbError>>>>,
        create_result: Arc<Mutex<Option<Result<SamlIdentityMappingRow, DbError>>>>,
    }

    #[async_trait::async_trait]
    impl SamlIdentityMappingStore for StubFederationMappingStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _provider_id: &str,
            _name_id: &str,
            _identity_public_id: &str,
            _ory_global_id: &str,
        ) -> Result<SamlIdentityMappingRow, DbError> {
            self.create_result
                .lock()
                .unwrap()
                .take()
                .expect("federation mapping create stub not configured")
        }

        async fn get_by_name_id(
            &self,
            _tenant_id: &str,
            _provider_id: &str,
            _name_id: &str,
        ) -> Result<SamlIdentityMappingRow, DbError> {
            self.get_by_name_id_result
                .lock()
                .unwrap()
                .take()
                .expect("federation mapping get stub not configured")
        }
    }

    #[derive(Clone, Default)]
    struct StubSchemaStore {
        get_by_schema_id_result: Arc<Mutex<Option<Result<IdentitySchemaRow, DbError>>>>,
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
            _tenant_id: &str,
            _schema_id: &str,
        ) -> Result<IdentitySchemaRow, DbError> {
            self.get_by_schema_id_result
                .lock()
                .unwrap()
                .take()
                .expect("schema stub not configured")
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

        async fn get_default(&self, _tenant_id: &str) -> Result<IdentitySchemaRow, DbError> {
            unimplemented!()
        }
    }

    #[derive(Clone, Default)]
    struct StubIdpKeys;

    #[async_trait::async_trait]
    impl SamlIdpKeyStore for StubIdpKeys {
        async fn create(
            &self,
            _tenant_id: &str,
            _key_id: &str,
            _private_key_pem: &str,
            _certificate_pem: &str,
            _is_active: bool,
        ) -> Result<SamlIdpKeyRow, DbError> {
            unimplemented!()
        }

        async fn get_active(&self, _tenant_id: &str) -> Result<SamlIdpKeyRow, DbError> {
            unimplemented!()
        }

        async fn list(&self, _tenant_id: &str) -> Result<Vec<SamlIdpKeyRow>, DbError> {
            unimplemented!()
        }
    }

    #[derive(Clone, Default)]
    struct StubConnectionStore {
        result: Arc<Mutex<Option<Result<crate::db::TenantConnectionRow, DbError>>>>,
    }

    impl StubConnectionStore {
        fn queue(&self, result: Result<crate::db::TenantConnectionRow, DbError>) {
            *self.result.lock().unwrap() = Some(result);
        }
    }

    #[async_trait::async_trait]
    impl TenantConnectionStore for StubConnectionStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _connection_type: crate::db::ConnectionType,
            _domain: &str,
            _config: serde_json::Value,
        ) -> Result<crate::db::TenantConnectionRow, DbError> {
            unimplemented!()
        }

        async fn get_by_domain(
            &self,
            _domain: &str,
        ) -> Result<crate::db::TenantConnectionRow, DbError> {
            Err(DbError::ConnectionNotFound)
        }

        async fn get_by_id(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<crate::db::TenantConnectionRow, DbError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(DbError::ConnectionNotFound))
        }

        async fn list_by_tenant(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<crate::db::TenantConnectionRow>, DbError> {
            Ok(vec![])
        }

        async fn update_config(
            &self,
            _tenant_id: &str,
            _id: &str,
            _config: serde_json::Value,
        ) -> Result<crate::db::TenantConnectionRow, DbError> {
            unimplemented!()
        }

        async fn set_enabled(
            &self,
            _tenant_id: &str,
            _id: &str,
            _is_enabled: bool,
        ) -> Result<crate::db::TenantConnectionRow, DbError> {
            unimplemented!()
        }
    }

    #[derive(Clone, Default)]
    struct StubDomainStore;

    #[derive(Clone, Default)]
    struct StubLoginStateStore {
        rows: Arc<Mutex<Vec<crate::db::LoginStateRow>>>,
    }

    #[async_trait::async_trait]
    impl LoginStateStore for StubLoginStateStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _connection_id: &str,
            connection_type: &str,
            return_to: &str,
            code_verifier: Option<String>,
            nonce: Option<String>,
            _ttl: std::time::Duration,
        ) -> Result<crate::db::LoginStateRow, DbError> {
            let row = crate::db::LoginStateRow {
                state_token: "state-1".into(),
                tenant_id: "tenant-1".into(),
                connection_id: "conn-1".into(),
                connection_type: connection_type.into(),
                return_to: return_to.into(),
                code_verifier,
                nonce,
                created_at: time::OffsetDateTime::now_utc(),
                expires_at: time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(900),
            };
            self.rows.lock().unwrap().push(row.clone());
            Ok(row)
        }

        async fn get(&self, _state_token: &str) -> Result<crate::db::LoginStateRow, DbError> {
            Err(DbError::LoginStateNotFound)
        }

        async fn delete(&self, _state_token: &str) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl TenantDomainStore for StubDomainStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _domain: &str,
        ) -> Result<crate::db::TenantDomainRow, DbError> {
            unimplemented!()
        }

        async fn get_by_domain(
            &self,
            _domain: &str,
        ) -> Result<crate::db::TenantDomainRow, DbError> {
            Err(DbError::DomainNotFound)
        }

        async fn mark_verified(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<crate::db::TenantDomainRow, DbError> {
            unimplemented!()
        }

        async fn list_by_tenant(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<crate::db::TenantDomainRow>, DbError> {
            Ok(vec![])
        }
    }

    #[derive(Clone, Default)]
    struct StubIdentityProvisioner;

    #[async_trait::async_trait]
    impl IdentityProvisioner for StubIdentityProvisioner {
        async fn provision(
            &self,
            tenant_id: &str,
            _schema_id: &str,
            claims: &serde_json::Value,
        ) -> Result<ProvisionedIdentity, crate::identity_provisioner::ProvisionError> {
            Ok(ProvisionedIdentity {
                tenant_id: tenant_id.to_string(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: claims["email"]
                    .as_str()
                    .unwrap_or("alice@example.com")
                    .to_string(),
            })
        }

        async fn provision_saml(
            &self,
            tenant_id: &str,
            _provider_id: &str,
            _schema_id: &str,
            _name_id: &str,
            email: &str,
            _email_verified: bool,
            _trusted_provider: bool,
        ) -> Result<ProvisionedIdentity, crate::identity_provisioner::ProvisionError> {
            Ok(ProvisionedIdentity {
                tenant_id: tenant_id.to_string(),
                public_id: "public-1".into(),
                ory_id: "ory-1".into(),
                email: email.to_string(),
            })
        }
    }

    impl Default for FederationServiceImpl {
        fn default() -> Self {
            let connections: Arc<dyn TenantConnectionStore> =
                Arc::new(StubConnectionStore::default());
            let domains: Arc<dyn TenantDomainStore> = Arc::new(StubDomainStore);
            let providers: Arc<dyn SamlProviderStore> = Arc::new(StubProviderStore::default());
            let hrd = crate::hrd::Hrd::new(
                connections.clone(),
                domains.clone(),
                providers.clone(),
                "http://gateway".into(),
            );
            Self {
                kratos: Arc::new(StubKratos::default()),
                providers,
                requests: Arc::new(StubRequestStore::default()),
                mappings: Arc::new(StubMappingStore::default()),
                federation_mappings: Arc::new(StubFederationMappingStore::default()),
                schemas: Arc::new(StubSchemaStore::default()),
                idp_keys: Arc::new(StubIdpKeys),
                connections,
                domains,
                login_state: Arc::new(StubLoginStateStore::default()),
                identity_provisioner: Arc::new(StubIdentityProvisioner),
                hrd,
                hydra_public_url: "http://hydra".into(),
                public_base_url: "http://gateway".into(),
                http: Arc::new(StubHydra::default()),
                saml_signer: None,
                sp_certificate_pem: None,
                request_ttl: Duration::from_secs(900),
                require_signed_assertions: false,
                require_signed_responses: false,
                replay_cache: Arc::new(InMemoryReplayCache::new()),
            }
        }
    }

    fn service_with_connection_and_login_state(
        connections: Arc<dyn TenantConnectionStore>,
        login_state: Arc<dyn LoginStateStore>,
    ) -> FederationServiceImpl {
        let providers: Arc<dyn SamlProviderStore> = Arc::new(StubProviderStore::default());
        let domains: Arc<dyn TenantDomainStore> = Arc::new(StubDomainStore);
        let hrd = crate::hrd::Hrd::new(
            connections.clone(),
            domains.clone(),
            providers.clone(),
            "http://gateway".into(),
        );
        FederationServiceImpl {
            kratos: Arc::new(StubKratos::default()),
            providers,
            requests: Arc::new(StubRequestStore::default()),
            mappings: Arc::new(StubMappingStore::default()),
            federation_mappings: Arc::new(StubFederationMappingStore::default()),
            schemas: Arc::new(StubSchemaStore::default()),
            idp_keys: Arc::new(StubIdpKeys),
            connections,
            domains,
            login_state,
            identity_provisioner: Arc::new(StubIdentityProvisioner),
            hrd,
            hydra_public_url: "http://hydra".into(),
            public_base_url: "https://gateway.example.com".into(),
            http: Arc::new(StubHydra::default()),
            saml_signer: None,
            sp_certificate_pem: None,
            request_ttl: Duration::from_secs(900),
            require_signed_assertions: false,
            require_signed_responses: false,
            replay_cache: Arc::new(InMemoryReplayCache::new()),
        }
    }

    fn build_test_response(request_id: &str, sp_entity_id: &str, acs_url: &str) -> SamlResponse {
        let options = ResponseOptions {
            idp_entity_id: "https://idp.example.com".to_string(),
            in_response_to: Some(request_id.to_string()),
            sp_entity_id: sp_entity_id.to_string(),
            acs_url: acs_url.to_string(),
            assertion_lifetime_seconds: 300,
            session_index: Some("_session_1".to_string()),
            session_not_on_or_after: None,
            authn_context_class_ref: Some(constants::AUTHN_CONTEXT_PASSWORD.to_string()),
            client_address: None,
            attributes: vec![Attribute {
                name: "email".to_string(),
                name_format: None,
                friendly_name: None,
                values: vec![AttributeValue::String("alice@example.com".to_string())],
            }],
        };
        let name_id = NameId {
            value: "alice@example.com".to_string(),
            format: Some(constants::NAMEID_EMAIL.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };
        create_response(&options, &name_id, ResponseTimes::at(Utc::now()))
    }

    #[test]
    fn test_build_test_response_serializes_and_processes() {
        let request_id = "_request_123";
        let sp_entity_id = "https://sp.example.com";
        let acs_url = "https://sp.example.com/acs";
        let response = build_test_response(request_id, sp_entity_id, acs_url);
        let xml = response.to_xml_string().expect("serialize response");

        let doc = parse_secure(&xml).expect("parse response");
        let parsed: SamlResponse = parse_saml::<SamlResponseRef>(&doc)
            .expect("parse saml response")
            .to_owned();

        let mut config = SecurityConfig::new();
        config.require_signed_assertions = false;
        config.require_signed_responses = false;
        config.require_encrypted_assertions = false;

        let replay_cache = InMemoryReplayCache::new();
        let result = process_response_with_verified_signatures(
            &parsed,
            &config,
            Some(&replay_cache),
            sp_entity_id,
            acs_url,
            Some(request_id),
            "https://idp.example.com",
            &[],
            Utc::now(),
        )
        .expect("process response");

        assert_eq!(result.name_id, "alice@example.com");
        assert_eq!(result.idp_entity_id, "https://idp.example.com");
    }

    #[test]
    fn test_resolve_acs_url_uses_absolute_when_provider_url_is_absolute() {
        assert_eq!(
            resolve_acs_url("http://gateway.example.com", "https://sp.example.com/acs"),
            "https://sp.example.com/acs"
        );
    }

    #[test]
    fn test_resolve_acs_url_prefixes_relative_path_with_public_base_url() {
        assert_eq!(
            resolve_acs_url("http://gateway.example.com", "/saml/acs"),
            "http://gateway.example.com/saml/acs"
        );
        assert_eq!(
            resolve_acs_url("http://gateway.example.com/", "/saml/acs"),
            "http://gateway.example.com/saml/acs"
        );
    }

    #[test]
    fn test_split_certificate_pem_blocks_extracts_multiple_certs() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";
        let blocks = split_certificate_pem_blocks(pem);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("AAAA"));
        assert!(blocks[1].contains("BBBB"));
    }

    #[test]
    fn test_key_info_from_certificate_pem_strips_headers() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        let key_info = key_info_from_certificate_pem(pem).expect("key info");
        assert!(key_info.contains("<ds:X509Certificate>MIIB</ds:X509Certificate>"));
        assert!(!key_info.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_json_str_extracts_or_defaults() {
        let value = json!({"a": "one", "b": 2});
        assert_eq!(json_str(&value, "a"), "one");
        assert_eq!(json_str(&value, "missing"), "");
        assert_eq!(json_str(&value, "b"), "");
    }

    #[test]
    fn test_json_str_array_extracts_strings() {
        let value = json!({"arr": ["a", "b", 1]});
        assert_eq!(json_str_array(&value, "arr"), vec!["a", "b"]);
        assert!(json_str_array(&value, "missing").is_empty());
    }

    #[test]
    fn test_json_web_key_to_proto_maps_fields() {
        let value = json!({
            "kty": "RSA",
            "use": "sig",
            "kid": "key-1",
            "alg": "RS256",
            "n": "abc",
            "e": "def"
        });
        let key = json_web_key_to_proto(value);
        assert_eq!(key.kty, "RSA");
        assert_eq!(key.r#use, "sig");
        assert_eq!(key.kid, "key-1");
        assert_eq!(key.n, "abc");
        assert_eq!(key.e, "def");
    }

    #[test]
    fn test_key_info_from_certificate_pem_returns_none_for_empty() {
        assert!(
            key_info_from_certificate_pem("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----")
                .is_none()
        );
    }

    #[test]
    fn test_verify_saml_signature_returns_empty_without_cert() {
        let ids = verify_saml_signature("<xml/>", None).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn test_verify_saml_signature_errors_for_bad_cert() {
        let err = verify_saml_signature("<xml/>", Some("not a certificate")).unwrap_err();
        assert!(matches!(
            err,
            gamlastan::crypto::error::CryptoError::KeyNotFound(_)
        ));
    }

    #[test]
    fn test_require_tenant_returns_tenant_id() {
        let mut ctx = RequestContext::new(http::HeaderMap::new());
        ctx.extensions_mut().insert(TenantId("tenant-1".into()));
        assert_eq!(require_tenant(&ctx).unwrap(), "tenant-1");
    }

    #[test]
    fn test_require_tenant_missing() {
        let ctx = RequestContext::new(http::HeaderMap::new());
        assert!(matches!(
            require_tenant(&ctx),
            Err(ServiceError::Unauthenticated(_))
        ));
    }

    #[tokio::test]
    async fn test_map_ory_error_maps_all_variants() {
        assert!(matches!(
            map_ory_error(OryClientError::Ory {
                status: 400,
                message: "bad".into()
            }),
            ServiceError::InvalidArgument(_)
        ));
        assert!(matches!(
            map_ory_error(OryClientError::Http(
                reqwest::get("http://localhost:1").await.unwrap_err()
            )),
            ServiceError::Unavailable(_)
        ));
        assert!(matches!(
            map_ory_error(OryClientError::Serialization(
                serde_json::from_str::<serde_json::Value>("not json").unwrap_err()
            )),
            ServiceError::Serialization(_)
        ));
        assert!(matches!(
            map_ory_error(OryClientError::Url(
                reqwest::Url::parse("not-a-url").unwrap_err()
            )),
            ServiceError::Configuration(_)
        ));
        assert!(matches!(
            map_ory_error(OryClientError::InvalidResponse("bad".into())),
            ServiceError::Internal(_)
        ));
        assert!(matches!(
            map_ory_error(OryClientError::MissingTenant),
            ServiceError::Unauthenticated(_)
        ));
    }

    #[tokio::test]
    async fn test_generate_sp_metadata_without_certificate() {
        // We do not need a real Postgres pool for generate_sp_metadata; any pool
        // value would do, so we create one pointing at localhost and accept that
        // it may fail to connect (the constructor only stores the pool).
        let pool = crate::db::create_pool("postgres://localhost:5432/unused", false)
            .await
            .unwrap_or_else(|_| {
                use sqlx::PgPool;
                PgPool::connect_lazy("postgres://localhost:5432/unused").unwrap()
            });
        let service = FederationServiceImpl::new(
            Arc::new(KratosClient::new_with_public("http://a", "http://b").unwrap()),
            SamlProviderRepo::new(pool.clone()),
            SamlRequestRepo::new(pool.clone()),
            IdMappingRepo::new(pool.clone()),
            SamlIdentityMappingRepo::new(pool.clone()),
            IdentitySchemaRepo::new(pool.clone()),
            SamlIdpKeyRepo::new(pool.clone()),
            TenantConnectionRepo::new(pool.clone()),
            TenantDomainRepo::new(pool.clone()),
            LoginStateRepo::new(pool),
            "http://hydra".into(),
            "http://gateway".into(),
            None,
            None,
            std::time::Duration::from_secs(900),
            true,
            false,
            Arc::new(InMemoryReplayCache::new()),
        );
        let provider = SamlProviderRow {
            id: "p1".into(),
            tenant_id: "t1".into(),
            name: "provider".into(),
            idp_entity_id: "https://idp.example.com".into(),
            idp_sso_url: "https://idp.example.com/sso".into(),
            idp_certificate_pem: None,
            sp_entity_id: "https://sp.example.com".into(),
            acs_url: "/saml/acs".into(),
            name_id_format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into()),
            schema_id: "default".into(),
            authn_requests_signed: false,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        };
        let xml = service.generate_sp_metadata(&provider).expect("metadata");
        assert!(xml.contains("entityID=\"https://sp.example.com\""));
        assert!(xml.contains("AssertionConsumerService"));
        assert!(xml.contains("http://gateway/saml/acs"));
    }

    #[test]
    fn test_json_web_key_to_proto_defaults_missing_fields() {
        let key = json_web_key_to_proto(json!({"kty": "EC", "kid": "k1"}));
        assert_eq!(key.kty, "EC");
        assert_eq!(key.kid, "k1");
        assert_eq!(key.r#use, "");
        assert_eq!(key.alg, "");
        assert_eq!(key.n, "");
        assert_eq!(key.e, "");
        assert_eq!(key.x, "");
        assert_eq!(key.y, "");
        assert_eq!(key.crv, "");
    }

    #[tokio::test]
    async fn test_generate_sp_metadata_with_certificate() {
        let cert_pem = include_str!("../../tests/fixtures/saml-test-cert.pem");
        let pool = crate::db::create_pool("postgres://localhost:5432/unused", false)
            .await
            .unwrap_or_else(|_| {
                use sqlx::PgPool;
                PgPool::connect_lazy("postgres://localhost:5432/unused").unwrap()
            });
        let service = FederationServiceImpl::new(
            Arc::new(KratosClient::new_with_public("http://a", "http://b").unwrap()),
            SamlProviderRepo::new(pool.clone()),
            SamlRequestRepo::new(pool.clone()),
            IdMappingRepo::new(pool.clone()),
            SamlIdentityMappingRepo::new(pool.clone()),
            IdentitySchemaRepo::new(pool.clone()),
            SamlIdpKeyRepo::new(pool.clone()),
            TenantConnectionRepo::new(pool.clone()),
            TenantDomainRepo::new(pool.clone()),
            LoginStateRepo::new(pool),
            "http://hydra".into(),
            "http://gateway".into(),
            None,
            Some(cert_pem.to_string()),
            std::time::Duration::from_secs(900),
            true,
            false,
            Arc::new(InMemoryReplayCache::new()),
        );
        let provider = SamlProviderRow {
            id: "p1".into(),
            tenant_id: "t1".into(),
            name: "provider".into(),
            idp_entity_id: "https://idp.example.com".into(),
            idp_sso_url: "https://idp.example.com/sso".into(),
            idp_certificate_pem: None,
            sp_entity_id: "https://sp.example.com".into(),
            acs_url: "/saml/acs".into(),
            name_id_format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into()),
            schema_id: "default".into(),
            authn_requests_signed: false,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        };
        let xml = service.generate_sp_metadata(&provider).expect("metadata");
        assert!(xml.contains("entityID=\"https://sp.example.com\""));
        assert!(xml.contains("KeyDescriptor"));
        assert!(xml.contains("WantAssertionsSigned"));
    }

    #[test]
    fn test_verify_saml_signature_with_cert_but_unsigned_xml() {
        let cert_pem = include_str!("../../tests/fixtures/saml-test-cert.pem");
        let result = verify_saml_signature("<xml/>", Some(cert_pem));
        assert!(result.is_err(), "unsigned xml should fail verification");
    }

    #[tokio::test]
    async fn test_federation_service_impl_new() {
        let pool = crate::db::create_pool("postgres://localhost:5432/unused", false)
            .await
            .unwrap_or_else(|_| {
                use sqlx::PgPool;
                PgPool::connect_lazy("postgres://localhost:5432/unused").unwrap()
            });
        let service = FederationServiceImpl::new(
            Arc::new(KratosClient::new_with_public("http://a", "http://b").unwrap()),
            SamlProviderRepo::new(pool.clone()),
            SamlRequestRepo::new(pool.clone()),
            IdMappingRepo::new(pool.clone()),
            SamlIdentityMappingRepo::new(pool.clone()),
            IdentitySchemaRepo::new(pool.clone()),
            SamlIdpKeyRepo::new(pool.clone()),
            TenantConnectionRepo::new(pool.clone()),
            TenantDomainRepo::new(pool.clone()),
            LoginStateRepo::new(pool),
            "http://hydra".into(),
            "http://gateway".into(),
            None,
            None,
            std::time::Duration::from_secs(900),
            true,
            false,
            Arc::new(InMemoryReplayCache::new()),
        );
        let _cloned = service.clone();
    }

    fn build_signed_response_xml() -> (String, String) {
        let request_id = "_request_123";
        let sp_entity_id = "https://sp.example.com";
        let acs_url = "https://sp.example.com/acs";
        let response = build_test_response(request_id, sp_entity_id, acs_url);
        let response_id = response.base.id.clone();
        let mut xml = response.to_xml_string().expect("serialize response");

        let template = format!(
            r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#{response_id}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue></ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue></ds:SignatureValue>
            <ds:KeyInfo><ds:X509Data/></ds:KeyInfo>
        </ds:Signature>"##
        );

        let status_pos = xml
            .find("<samlp:Status")
            .expect("status element in serialized response");
        xml.insert_str(status_pos, &template);

        let key_pem = include_bytes!("../../tests/fixtures/saml-test-key.pem");
        let key_manager =
            gamlastan::crypto::keys::build_idp_keys_manager(key_pem).expect("load saml test key");
        let signer = gamlastan::crypto::SamlSigner::new(key_manager);
        let signed_xml = signer.sign_enveloped(&xml).expect("sign saml response");

        (signed_xml, response_id)
    }

    #[test]
    fn test_verify_saml_signature_with_valid_signed_xml() {
        let cert_pem = include_str!("../../tests/fixtures/saml-test-cert.pem");
        let (signed_xml, response_id) = build_signed_response_xml();
        let ids = verify_saml_signature(&signed_xml, Some(cert_pem)).expect("verify signed xml");
        assert_eq!(ids, vec![response_id]);
    }

    #[tokio::test]
    async fn test_get_open_id_configuration_ok() {
        let hydra = Arc::new(StubHydra {
            discovery_result: Arc::new(Mutex::new(Some(Ok(json!({
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://auth",
                "token_endpoint": "https://token",
                "userinfo_endpoint": "https://userinfo",
                "jwks_uri": "https://jwks",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "scopes_supported": ["openid"],
            }))))),
            ..Default::default()
        });
        let service = FederationServiceImpl {
            http: hydra,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = GetOpenIDConfigurationRequest::default();
        svc_req!(request, proto_req, GetOpenIDConfigurationRequest);

        let resp = service
            .get_open_id_configuration(ctx, request)
            .await
            .expect("openid configuration");

        assert_eq!(resp.body.issuer, "https://issuer.example.com");
        assert_eq!(resp.body.authorization_endpoint, "https://auth");
        assert_eq!(resp.body.scopes_supported, vec!["openid"]);
        assert_eq!(resp.body.grant_types_supported, vec!["authorization_code"]);
    }

    #[tokio::test]
    async fn test_get_open_id_configuration_hydra_error() {
        let hydra = Arc::new(StubHydra {
            discovery_result: Arc::new(Mutex::new(Some(Err(ServiceError::Unavailable(
                "hydra down".into(),
            ))))),
            ..Default::default()
        });
        let service = FederationServiceImpl {
            http: hydra,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = GetOpenIDConfigurationRequest::default();
        svc_req!(request, proto_req, GetOpenIDConfigurationRequest);

        let err = service
            .get_open_id_configuration(ctx, request)
            .await
            .expect_err("should fail");
        assert_eq!(err.code, connectrpc::ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn test_get_json_web_keys_ok() {
        let hydra = Arc::new(StubHydra {
            jwks_result: Arc::new(Mutex::new(Some(Ok(json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "key-1",
                        "alg": "RS256",
                        "n": "abc",
                        "e": "def"
                    }
                ]
            }))))),
            ..Default::default()
        });
        let service = FederationServiceImpl {
            http: hydra,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = GetJSONWebKeysRequest::default();
        svc_req!(request, proto_req, GetJSONWebKeysRequest);

        let resp = service.get_json_web_keys(ctx, request).await.expect("jwks");
        assert_eq!(resp.body.keys.len(), 1);
        let key = &resp.body.keys[0];
        assert_eq!(key.kid, "key-1");
        assert_eq!(key.kty, "RSA");
    }

    #[tokio::test]
    async fn test_initiate_saml_login_ok() {
        let provider = test_provider();
        let providers = Arc::new(StubProviderStore {
            provider: Arc::new(Mutex::new(Some(Ok(provider.clone())))),
        });
        let requests = Arc::new(StubRequestStore {
            create_result: Arc::new(Mutex::new(Some(Ok(SamlRequestRow {
                id: "request-id".into(),
                tenant_id: "tenant-1".into(),
                provider_id: provider.id.clone(),
                relay_state: "relay-1".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })))),
            ..Default::default()
        });
        let service = FederationServiceImpl {
            providers,
            requests,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = InitiateSamlLoginRequest {
            provider_id: provider.id.clone(),
            relay_state: "relay-1".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, InitiateSamlLoginRequest);

        let resp = service
            .initiate_saml_login(ctx, request)
            .await
            .expect("initiate login");

        assert!(
            resp.body
                .redirect_url
                .contains("https://idp.example.com/sso")
        );
        assert!(!resp.body.request_id.is_empty());
    }

    #[tokio::test]
    async fn test_initiate_saml_login_provider_not_found() {
        let providers = Arc::new(StubProviderStore {
            provider: Arc::new(Mutex::new(Some(Err(DbError::SamlProviderNotFound)))),
        });
        let service = FederationServiceImpl {
            providers,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = InitiateSamlLoginRequest {
            provider_id: "missing".into(),
            relay_state: "relay-1".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, InitiateSamlLoginRequest);

        let err = service
            .initiate_saml_login(ctx, request)
            .await
            .expect_err("should fail");
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn test_initiate_saml_login_missing_signer() {
        let mut provider = test_provider();
        provider.authn_requests_signed = true;
        let providers = Arc::new(StubProviderStore {
            provider: Arc::new(Mutex::new(Some(Ok(provider)))),
        });
        let service = FederationServiceImpl {
            providers,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = InitiateSamlLoginRequest {
            provider_id: "provider-1".into(),
            relay_state: "relay-1".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, InitiateSamlLoginRequest);

        let err = service
            .initiate_saml_login(ctx, request)
            .await
            .expect_err("should fail");
        assert_eq!(err.code, connectrpc::ErrorCode::Internal);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_accept_saml_assertion_existing_mapping() {
        let provider = test_provider();
        let request_id = "_request_123";
        let response = build_test_response(request_id, &provider.sp_entity_id, &provider.acs_url);
        let encoded = encode_saml_response(&response);

        let providers = Arc::new(StubProviderStore {
            provider: Arc::new(Mutex::new(Some(Ok(provider.clone())))),
        });
        let requests = Arc::new(StubRequestStore {
            get_result: Arc::new(Mutex::new(Some(Ok(SamlRequestRow {
                id: request_id.into(),
                tenant_id: "tenant-1".into(),
                provider_id: provider.id.clone(),
                relay_state: "relay-1".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })))),
            delete_ok: Arc::new(Mutex::new(true)),
            ..Default::default()
        });
        let federation_mappings = Arc::new(StubFederationMappingStore {
            get_by_name_id_result: Arc::new(Mutex::new(Some(Ok(SamlIdentityMappingRow {
                id: "mapping-1".into(),
                tenant_id: "tenant-1".into(),
                provider_id: provider.id.clone(),
                name_id: "alice@example.com".into(),
                identity_public_id: "public-1".into(),
                ory_global_id: "ory-1".into(),
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
            ..Default::default()
        });
        let schemas = Arc::new(StubSchemaStore {
            get_by_schema_id_result: Arc::new(Mutex::new(Some(Ok(test_schema())))),
        });

        let service = FederationServiceImpl {
            providers,
            requests,
            federation_mappings,
            schemas,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = AcceptSamlAssertionRequest {
            encoded_assertion: encoded,
            relay_state: "relay-1".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, AcceptSamlAssertionRequest);

        let resp = service
            .accept_saml_assertion(ctx, request)
            .await
            .expect("accept assertion");

        assert_eq!(resp.body.identity_id, "public-1");
        assert_eq!(resp.body.tenant_id, "tenant-1");
        assert!(resp.body.active);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_accept_saml_assertion_creates_new_identity() {
        let provider = test_provider();
        let request_id = "_request_123";
        let response = build_test_response(request_id, &provider.sp_entity_id, &provider.acs_url);
        let encoded = encode_saml_response(&response);

        let providers = Arc::new(StubProviderStore {
            provider: Arc::new(Mutex::new(Some(Ok(provider.clone())))),
        });
        let requests = Arc::new(StubRequestStore {
            get_result: Arc::new(Mutex::new(Some(Ok(SamlRequestRow {
                id: request_id.into(),
                tenant_id: "tenant-1".into(),
                provider_id: provider.id.clone(),
                relay_state: "relay-1".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })))),
            delete_ok: Arc::new(Mutex::new(true)),
            ..Default::default()
        });
        let federation_mappings = Arc::new(StubFederationMappingStore {
            get_by_name_id_result: Arc::new(Mutex::new(Some(Err(
                DbError::SamlIdentityMappingNotFound,
            )))),
            create_result: Arc::new(Mutex::new(Some(Ok(SamlIdentityMappingRow {
                id: "mapping-1".into(),
                tenant_id: "tenant-1".into(),
                provider_id: provider.id.clone(),
                name_id: "alice@example.com".into(),
                identity_public_id: "public-1".into(),
                ory_global_id: "ory-1".into(),
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let mappings = Arc::new(StubMappingStore {
            create_result: Arc::new(Mutex::new(Some(Ok(IdMappingRow {
                id: "id-1".into(),
                tenant_id: "tenant-1".into(),
                backend: BACKEND_KRATOS.into(),
                public_id: "public-1".into(),
                ory_global_id: "ory-1".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let schemas = Arc::new(StubSchemaStore {
            get_by_schema_id_result: Arc::new(Mutex::new(Some(Ok(test_schema())))),
        });
        let kratos = Arc::new(StubKratos {
            create_identity_result: Arc::new(Mutex::new(Some(Ok(json!({"id": "ory-1"}))))),
        });

        let service = FederationServiceImpl {
            kratos,
            providers,
            requests,
            mappings,
            federation_mappings,
            schemas,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = AcceptSamlAssertionRequest {
            encoded_assertion: encoded,
            relay_state: "relay-1".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, AcceptSamlAssertionRequest);

        let resp = service
            .accept_saml_assertion(ctx, request)
            .await
            .expect("accept assertion");

        assert!(!resp.body.identity_id.is_empty());
    }

    #[tokio::test]
    async fn test_accept_saml_assertion_invalid_base64() {
        let service = FederationServiceImpl::default();
        let ctx = tenant_context("tenant-1");
        let proto_req = AcceptSamlAssertionRequest {
            encoded_assertion: "not-valid-base64!!!".into(),
            relay_state: "relay-1".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, AcceptSamlAssertionRequest);

        let err = service
            .accept_saml_assertion(ctx, request)
            .await
            .expect_err("should fail");
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn test_accept_saml_assertion_relay_state_mismatch() {
        let provider = test_provider();
        let request_id = "_request_123";
        let response = build_test_response(request_id, &provider.sp_entity_id, &provider.acs_url);
        let encoded = encode_saml_response(&response);

        let providers = Arc::new(StubProviderStore {
            provider: Arc::new(Mutex::new(Some(Ok(provider.clone())))),
        });
        let requests = Arc::new(StubRequestStore {
            get_result: Arc::new(Mutex::new(Some(Ok(SamlRequestRow {
                id: request_id.into(),
                tenant_id: "tenant-1".into(),
                provider_id: provider.id.clone(),
                relay_state: "different-state".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })))),
            ..Default::default()
        });

        let service = FederationServiceImpl {
            providers,
            requests,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = AcceptSamlAssertionRequest {
            encoded_assertion: encoded,
            relay_state: "relay-1".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, AcceptSamlAssertionRequest);

        let err = service
            .accept_saml_assertion(ctx, request)
            .await
            .expect_err("should fail");
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn test_accept_saml_assertion_expired_request() {
        let provider = test_provider();
        let request_id = "_request_123";
        let response = build_test_response(request_id, &provider.sp_entity_id, &provider.acs_url);
        let encoded = encode_saml_response(&response);

        let providers = Arc::new(StubProviderStore {
            provider: Arc::new(Mutex::new(Some(Ok(provider.clone())))),
        });
        let requests = Arc::new(StubRequestStore {
            get_result: Arc::new(Mutex::new(Some(Ok(SamlRequestRow {
                id: request_id.into(),
                tenant_id: "tenant-1".into(),
                provider_id: provider.id.clone(),
                relay_state: "relay-1".into(),
                created_at: time::OffsetDateTime::now_utc() - Duration::from_secs(1000),
            })))),
            ..Default::default()
        });

        let service = FederationServiceImpl {
            providers,
            requests,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = AcceptSamlAssertionRequest {
            encoded_assertion: encoded,
            relay_state: "relay-1".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, AcceptSamlAssertionRequest);

        let err = service
            .accept_saml_assertion(ctx, request)
            .await
            .expect_err("should fail");
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn test_accept_saml_assertion_request_not_found() {
        let provider = test_provider();
        let request_id = "_request_123";
        let response = build_test_response(request_id, &provider.sp_entity_id, &provider.acs_url);
        let encoded = encode_saml_response(&response);

        let requests = Arc::new(StubRequestStore {
            get_result: Arc::new(Mutex::new(Some(Err(DbError::SamlRequestNotFound)))),
            ..Default::default()
        });

        let service = FederationServiceImpl {
            requests,
            ..Default::default()
        };
        let ctx = tenant_context("tenant-1");
        let proto_req = AcceptSamlAssertionRequest {
            encoded_assertion: encoded,
            relay_state: "relay-1".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, AcceptSamlAssertionRequest);

        let err = service
            .accept_saml_assertion(ctx, request)
            .await
            .expect_err("should fail");
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    fn oidc_connection_row() -> crate::db::TenantConnectionRow {
        crate::db::TenantConnectionRow {
            id: "conn-oidc".into(),
            tenant_id: "tenant-1".into(),
            connection_type: crate::db::ConnectionType::Oidc,
            domain: "idp.example.com".into(),
            config: json!({
                "client_id": "client-1",
                "client_secret": "secret-1",
                "issuer": "https://idp.example.com",
                "authorization_endpoint": "https://idp.example.com/authorize",
                "token_url": "https://idp.example.com/token",
                "userinfo_url": "https://idp.example.com/userinfo",
                "scopes": ["openid", "profile"],
            }),
            is_enabled: true,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn oauth2_connection_row() -> crate::db::TenantConnectionRow {
        crate::db::TenantConnectionRow {
            id: "conn-oauth2".into(),
            tenant_id: "tenant-1".into(),
            connection_type: crate::db::ConnectionType::OAuth2,
            domain: "idp.example.com".into(),
            config: json!({
                "client_id": "client-1",
                "client_secret": "secret-1",
                "authorization_url": "https://idp.example.com/authorize",
                "token_url": "https://idp.example.com/token",
                "userinfo_url": "https://idp.example.com/userinfo",
                "scopes": ["profile"],
            }),
            is_enabled: true,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    #[tokio::test]
    async fn test_initiate_oidc_login_includes_pkce_and_nonce() {
        let connections = Arc::new(StubConnectionStore::default());
        connections.queue(Ok(oidc_connection_row()));
        let login_state = Arc::new(StubLoginStateStore::default());
        let service = service_with_connection_and_login_state(connections, login_state.clone());
        let ctx = tenant_context("tenant-1");
        let proto_req = InitiateOidcLoginRequest {
            connection_id: "conn-oidc".into(),
            return_to: "https://app.example.com".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, InitiateOidcLoginRequest);

        let resp = service
            .initiate_oidc_login(ctx, request)
            .await
            .expect("initiate oidc login");

        let url = resp.body.authorization_url;
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("nonce="));
        let rows = login_state.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].code_verifier.is_some());
        assert!(rows[0].nonce.is_some());
    }

    #[tokio::test]
    async fn test_initiate_oauth2_login_includes_pkce() {
        let connections = Arc::new(StubConnectionStore::default());
        connections.queue(Ok(oauth2_connection_row()));
        let login_state = Arc::new(StubLoginStateStore::default());
        let service = service_with_connection_and_login_state(connections, login_state.clone());
        let ctx = tenant_context("tenant-1");
        let proto_req = InitiateOAuth2LoginRequest {
            connection_id: "conn-oauth2".into(),
            return_to: "https://app.example.com".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, InitiateOAuth2LoginRequest);

        let resp = service
            .initiate_o_auth2_login(ctx, request)
            .await
            .expect("initiate oauth2 login");

        let url = resp.body.authorization_url;
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(!url.contains("nonce="));
        let rows = login_state.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].code_verifier.is_some());
        assert!(rows[0].nonce.is_none());
    }

    #[tokio::test]
    async fn test_initiate_oidc_login_rejects_http_url() {
        let mut row = oidc_connection_row();
        row.config["issuer"] = "http://idp.example.com".into();
        row.config["authorization_endpoint"] = "http://idp.example.com/authorize".into();
        let connections = Arc::new(StubConnectionStore::default());
        connections.queue(Ok(row));
        let service = service_with_connection_and_login_state(
            connections,
            Arc::new(StubLoginStateStore::default()),
        );
        let ctx = tenant_context("tenant-1");
        let proto_req = InitiateOidcLoginRequest {
            connection_id: "conn-oidc".into(),
            return_to: "https://app.example.com".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, InitiateOidcLoginRequest);

        let err = service
            .initiate_oidc_login(ctx, request)
            .await
            .expect_err("should fail");
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn test_initiate_oauth2_login_rejects_loopback_url() {
        let mut row = oauth2_connection_row();
        row.config["authorization_url"] = "https://127.0.0.1/authorize".into();
        let connections = Arc::new(StubConnectionStore::default());
        connections.queue(Ok(row));
        let service = service_with_connection_and_login_state(
            connections,
            Arc::new(StubLoginStateStore::default()),
        );
        let ctx = tenant_context("tenant-1");
        let proto_req = InitiateOAuth2LoginRequest {
            connection_id: "conn-oauth2".into(),
            return_to: "https://app.example.com".into(),
            ..Default::default()
        };
        svc_req!(request, proto_req, InitiateOAuth2LoginRequest);

        let err = service
            .initiate_o_auth2_login(ctx, request)
            .await
            .expect_err("should fail");
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[test]
    fn test_compute_code_challenge_is_s256() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_code_challenge(verifier);
        // Known S256 test vector from RFC 7636 appendix B.
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn test_generate_code_verifier_and_nonce_are_random() {
        let v1 = generate_code_verifier();
        let v2 = generate_code_verifier();
        assert_ne!(v1, v2);
        assert!(!v1.is_empty());

        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
        assert!(!n1.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_process_saml_assertion_fail_closed_without_certificate() {
        let mut provider = test_provider();
        provider.idp_certificate_pem = None;
        let request_id = "_request_123";
        let response = build_test_response(request_id, &provider.sp_entity_id, &provider.acs_url);
        let encoded = encode_saml_response(&response);

        let providers = Arc::new(StubProviderStore {
            provider: Arc::new(Mutex::new(Some(Ok(provider.clone())))),
        });
        let requests = Arc::new(StubRequestStore {
            get_result: Arc::new(Mutex::new(Some(Ok(SamlRequestRow {
                id: request_id.into(),
                tenant_id: "tenant-1".into(),
                provider_id: provider.id.clone(),
                relay_state: "relay-1".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })))),
            delete_ok: Arc::new(Mutex::new(true)),
            ..Default::default()
        });

        let service = FederationServiceImpl {
            providers,
            requests,
            require_signed_assertions: true,
            ..Default::default()
        };

        let err = service
            .process_saml_assertion("tenant-1", &provider, &encoded, request_id)
            .await
            .expect_err("should fail");
        assert!(matches!(err, ServiceError::Configuration(_)));
    }

    async fn start_hydra_server() -> (tokio::task::JoinHandle<()>, String) {
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(|| async {
                    Json(json!({
                        "issuer": "https://issuer.example.com",
                        "authorization_endpoint": "https://auth",
                        "token_endpoint": "https://token",
                        "userinfo_endpoint": "https://userinfo",
                        "jwks_uri": "https://jwks",
                    }))
                }),
            )
            .route(
                "/oauth2/jwks.json",
                get(|| async {
                    Json(json!({
                        "keys": [{
                            "kty": "RSA",
                            "use": "sig",
                            "kid": "key-1",
                            "alg": "RS256",
                            "n": "abc",
                            "e": "def"
                        }]
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (handle, format!("http://{addr}"))
    }

    #[tokio::test]
    async fn test_reqwest_client_as_federation_hydra_hits_server() {
        let (_handle, url) = start_hydra_server().await;
        let client = reqwest::Client::new();
        let discovery = client
            .fetch_discovery(&format!("{url}/.well-known/openid-configuration"))
            .await
            .unwrap();
        assert_eq!(discovery["issuer"], "https://issuer.example.com");

        let jwks = client
            .fetch_jwks(&format!("{url}/oauth2/jwks.json"))
            .await
            .unwrap();
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_kratos_client_as_federation_kratos_delegates() {
        let client =
            Arc::new(KratosClient::new("http://localhost:1").unwrap()) as Arc<dyn FederationKratos>;
        let err = client
            .create_identity(json!({"traits": {}}))
            .await
            .unwrap_err();
        assert!(matches!(err, OryClientError::Http(_)));
    }
}
