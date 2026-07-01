use std::sync::Arc;
use std::time::Duration;

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
use sso_ory_client::kratos::KratosClient;
use sunbeam_g2v::error::ServiceError;
use tracing::{debug, instrument};
use ulid::Ulid;

use crate::db::{
    IdMappingRepo, IdMappingStore, IdentitySchemaRepo, IdentitySchemaStore,
    SamlIdentityMappingRepo, SamlIdentityMappingStore, SamlIdpKeyRepo, SamlIdpKeyStore,
    SamlProviderRepo, SamlProviderRow, SamlProviderStore, SamlRequestRepo, SamlRequestStore,
};
use crate::middleware::TenantId;
use crate::proto::iam::v1::{
    AcceptSamlAssertionRequest, FederationService, GetJSONWebKeysRequest,
    GetOpenIDConfigurationRequest, InitiateSamlLoginRequest, JSONWebKey, JSONWebKeySet,
    OpenIDConfiguration, SamlLoginResponse, Session,
};

const BACKEND_KRATOS: &str = "kratos";

#[async_trait::async_trait]
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
pub struct FederationServiceImpl {
    kratos: Arc<dyn FederationKratos>,
    pub(crate) providers: Arc<dyn SamlProviderStore>,
    requests: Arc<dyn SamlRequestStore>,
    mappings: Arc<dyn IdMappingStore>,
    federation_mappings: Arc<dyn SamlIdentityMappingStore>,
    schemas: Arc<dyn IdentitySchemaStore>,
    #[allow(dead_code)]
    idp_keys: Arc<dyn SamlIdpKeyStore>,
    hydra_public_url: String,
    public_base_url: String,
    http: Arc<dyn FederationHydra>,
    saml_signer: Option<Arc<SamlSigner>>,
    sp_certificate_pem: Option<String>,
    request_ttl: Duration,
    require_signed_assertions: bool,
    require_signed_responses: bool,
    replay_cache: Arc<dyn gamlastan::security::ReplayCache>,
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
        hydra_public_url: String,
        public_base_url: String,
        saml_signer: Option<Arc<SamlSigner>>,
        sp_certificate_pem: Option<String>,
        request_ttl: Duration,
        require_signed_assertions: bool,
        require_signed_responses: bool,
        replay_cache: Arc<dyn gamlastan::security::ReplayCache>,
    ) -> Self {
        Self {
            kratos: kratos as Arc<dyn FederationKratos>,
            providers: Arc::new(providers) as Arc<dyn SamlProviderStore>,
            requests: Arc::new(requests) as Arc<dyn SamlRequestStore>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            federation_mappings: Arc::new(federation_mappings)
                as Arc<dyn SamlIdentityMappingStore>,
            schemas: Arc::new(schemas) as Arc<dyn IdentitySchemaStore>,
            idp_keys: Arc::new(idp_keys) as Arc<dyn SamlIdpKeyStore>,
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

        let saml_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &req.encoded_assertion,
        )
        .map_err(|e| ServiceError::InvalidArgument(format!("base64: {e}")))?;
        let saml_xml = String::from_utf8(saml_bytes)
            .map_err(|e| ServiceError::InvalidArgument(format!("utf8: {e}")))?;

        let doc = parse_secure(&saml_xml)
            .map_err(|e| ServiceError::InvalidArgument(format!("saml parse: {e}")))?;
        let response: SamlResponse = parse_saml::<SamlResponseRef>(&doc)
            .map_err(|e| ServiceError::InvalidArgument(format!("saml response: {e}")))?
            .to_owned();

        let request_id = response
            .base
            .in_response_to
            .as_deref()
            .ok_or_else(|| ServiceError::InvalidArgument("unsolicited saml response".into()))?;

        let pending = self.requests.get(&tenant_id, request_id).await?;
        let provider = self.providers.get(&tenant_id, &pending.provider_id).await?;

        if req.relay_state != pending.relay_state {
            return Err(ServiceError::InvalidArgument("relay state mismatch".into()).into());
        }

        let request_age = time::OffsetDateTime::now_utc() - pending.created_at;
        if request_age.whole_seconds() > self.request_ttl.as_secs() as i64 {
            return Err(ServiceError::InvalidArgument("saml request expired".into()).into());
        }

        let verified_signed_ids =
            verify_saml_signature(&saml_xml, provider.idp_certificate_pem.as_deref())
                .map_err(|e| ServiceError::InvalidArgument(format!("saml signature: {e}")))?;

        let mut config = SecurityConfig::new();
        let has_idp_cert = provider.idp_certificate_pem.is_some();
        config.require_signed_assertions = has_idp_cert && self.require_signed_assertions;
        config.require_signed_responses = has_idp_cert && self.require_signed_responses;
        config.require_encrypted_assertions = false;

        let signed_ids: Vec<&str> = verified_signed_ids.iter().map(|s| s.as_str()).collect();
        let result = process_response_with_verified_signatures(
            &response,
            &config,
            Some(self.replay_cache.as_ref()),
            &provider.sp_entity_id,
            &provider.acs_url,
            Some(request_id),
            &provider.idp_entity_id,
            &signed_ids,
            Utc::now(),
        )
        .map_err(|e| ServiceError::InvalidArgument(format!("saml validation: {e}")))?;

        self.requests.delete(&tenant_id, request_id).await.ok();

        // Validate the identity schema registered for this tenant.
        let _schema = self
            .schemas
            .get_by_schema_id(&tenant_id, &provider.schema_id)
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

        let (public_id, _ory_id) = match self
            .federation_mappings
            .get_by_name_id(&tenant_id, &provider.id, &name_id)
            .await
        {
            Ok(mapping) => (mapping.identity_public_id, mapping.ory_global_id),
            Err(_) => {
                let payload = serde_json::json!({
                    "schema_id": provider.schema_id,
                    "traits": { "email": email },
                });
                let created = self
                    .kratos
                    .create_identity(payload)
                    .await
                    .map_err(map_ory_error)?;
                let ory_id = created["id"]
                    .as_str()
                    .ok_or_else(|| ServiceError::Internal("kratos response missing id".into()))?;
                let public_id = Ulid::new().to_string();
                self.mappings
                    .create(&tenant_id, BACKEND_KRATOS, &public_id, ory_id)
                    .await?;
                self.federation_mappings
                    .create(&tenant_id, &provider.id, &name_id, &public_id, ory_id)
                    .await?;
                (public_id, ory_id.to_string())
            }
        };

        let session_id = Ulid::new().to_string();
        Ok(Response::new(Session {
            id: session_id,
            identity_id: public_id,
            tenant_id,
            active: true,
            ..Default::default()
        }))
    }
}

impl FederationServiceImpl {
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

fn require_tenant(ctx: &RequestContext) -> Result<String, ServiceError> {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .ok_or_else(|| ServiceError::Unauthenticated("missing x-tenant-id".into()))
}

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
    use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
    use gamlastan::core::assertion::name_id::NameId;
    use gamlastan::core::constants;
    use gamlastan::profiles::sso::idp::create_response;
    use gamlastan::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
    use gamlastan::security::InMemoryReplayCache;
    use gamlastan::xml::SamlSerialize;
    use axum::{Json, Router, routing::get};
    use serde_json::json;
    use sso_ory_client::error::OryClientError;
    use sso_ory_client::kratos::KratosClient;
    use std::sync::Mutex;

    use crate::db::{
        DbError, IdMappingRow, IdentitySchemaRow, SamlIdpKeyRow, SamlIdentityMappingRow,
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

        async fn get(&self, _tenant_id: &str, _request_id: &str) -> Result<SamlRequestRow, DbError> {
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

    fn service_with_stubs(
        kratos: Arc<dyn FederationKratos>,
        providers: Arc<dyn SamlProviderStore>,
        requests: Arc<dyn SamlRequestStore>,
        mappings: Arc<dyn IdMappingStore>,
        federation_mappings: Arc<dyn SamlIdentityMappingStore>,
        schemas: Arc<dyn IdentitySchemaStore>,
        http: Arc<dyn FederationHydra>,
    ) -> FederationServiceImpl {
        FederationServiceImpl {
            kratos,
            providers,
            requests,
            mappings,
            federation_mappings,
            schemas,
            idp_keys: Arc::new(StubIdpKeys),
            hydra_public_url: "http://hydra".into(),
            public_base_url: "http://gateway".into(),
            http,
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
        let pool = crate::db::create_pool("postgres://localhost:5432/unused")
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
            SamlIdpKeyRepo::new(pool),
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
        let pool = crate::db::create_pool("postgres://localhost:5432/unused")
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
            SamlIdpKeyRepo::new(pool),
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
        let pool = crate::db::create_pool("postgres://localhost:5432/unused")
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
            SamlIdpKeyRepo::new(pool),
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
        let key_manager = gamlastan::crypto::keys::build_idp_keys_manager(key_pem)
            .expect("load saml test key");
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
        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            Arc::new(StubProviderStore::default()),
            Arc::new(StubRequestStore::default()),
            Arc::new(StubMappingStore::default()),
            Arc::new(StubFederationMappingStore::default()),
            Arc::new(StubSchemaStore::default()),
            hydra,
        );
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
        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            Arc::new(StubProviderStore::default()),
            Arc::new(StubRequestStore::default()),
            Arc::new(StubMappingStore::default()),
            Arc::new(StubFederationMappingStore::default()),
            Arc::new(StubSchemaStore::default()),
            hydra,
        );
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
        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            Arc::new(StubProviderStore::default()),
            Arc::new(StubRequestStore::default()),
            Arc::new(StubMappingStore::default()),
            Arc::new(StubFederationMappingStore::default()),
            Arc::new(StubSchemaStore::default()),
            hydra,
        );
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
        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            providers,
            requests,
            Arc::new(StubMappingStore::default()),
            Arc::new(StubFederationMappingStore::default()),
            Arc::new(StubSchemaStore::default()),
            Arc::new(StubHydra::default()),
        );
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

        assert!(resp.body.redirect_url.contains("https://idp.example.com/sso"));
        assert!(!resp.body.request_id.is_empty());
    }

    #[tokio::test]
    async fn test_initiate_saml_login_provider_not_found() {
        let providers = Arc::new(StubProviderStore {
            provider: Arc::new(Mutex::new(Some(Err(DbError::SamlProviderNotFound)))),
        });
        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            providers,
            Arc::new(StubRequestStore::default()),
            Arc::new(StubMappingStore::default()),
            Arc::new(StubFederationMappingStore::default()),
            Arc::new(StubSchemaStore::default()),
            Arc::new(StubHydra::default()),
        );
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
        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            providers,
            Arc::new(StubRequestStore::default()),
            Arc::new(StubMappingStore::default()),
            Arc::new(StubFederationMappingStore::default()),
            Arc::new(StubSchemaStore::default()),
            Arc::new(StubHydra::default()),
        );
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

    #[tokio::test]
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

        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            providers,
            requests,
            Arc::new(StubMappingStore::default()),
            federation_mappings,
            schemas,
            Arc::new(StubHydra::default()),
        );
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

    #[tokio::test]
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

        let service = service_with_stubs(
            kratos,
            providers,
            requests,
            mappings,
            federation_mappings,
            schemas,
            Arc::new(StubHydra::default()),
        );
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
        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            Arc::new(StubProviderStore::default()),
            Arc::new(StubRequestStore::default()),
            Arc::new(StubMappingStore::default()),
            Arc::new(StubFederationMappingStore::default()),
            Arc::new(StubSchemaStore::default()),
            Arc::new(StubHydra::default()),
        );
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

        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            providers,
            requests,
            Arc::new(StubMappingStore::default()),
            Arc::new(StubFederationMappingStore::default()),
            Arc::new(StubSchemaStore::default()),
            Arc::new(StubHydra::default()),
        );
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

        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            providers,
            requests,
            Arc::new(StubMappingStore::default()),
            Arc::new(StubFederationMappingStore::default()),
            Arc::new(StubSchemaStore::default()),
            Arc::new(StubHydra::default()),
        );
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

        let service = service_with_stubs(
            Arc::new(StubKratos::default()),
            Arc::new(StubProviderStore::default()),
            requests,
            Arc::new(StubMappingStore::default()),
            Arc::new(StubFederationMappingStore::default()),
            Arc::new(StubSchemaStore::default()),
            Arc::new(StubHydra::default()),
        );
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
        let discovery = client.fetch_discovery(&format!("{url}/.well-known/openid-configuration")).await.unwrap();
        assert_eq!(discovery["issuer"], "https://issuer.example.com");

        let jwks = client.fetch_jwks(&format!("{url}/oauth2/jwks.json")).await.unwrap();
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_kratos_client_as_federation_kratos_delegates() {
        let client = Arc::new(KratosClient::new("http://localhost:1").unwrap()) as Arc<dyn FederationKratos>;
        let err = client.create_identity(json!({"traits": {}})).await.unwrap_err();
        assert!(matches!(err, OryClientError::Http(_)));
    }
}
