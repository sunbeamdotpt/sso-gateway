use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Query, Request, State},
    http::{Response, StatusCode},
    response::IntoResponse,
    routing::get,
};
use base64::Engine;
use chrono::Utc;
use gamlastan::bindings::redirect::{redirect_decode, redirect_verify_signature};
use gamlastan::bindings::traits::HttpRequest;
use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
use gamlastan::core::assertion::name_id::NameId;
use gamlastan::core::constants;
use gamlastan::core::protocol::request::{AuthnRequest, AuthnRequestRef};
use gamlastan::crypto::keys::build_idp_keys_manager;
use gamlastan::crypto::{SamlSigner, SamlVerifier};
use gamlastan::profiles::sso::idp::create_response;
use gamlastan::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
use gamlastan::xml::{SamlSerialize, parse_saml, parse_secure};
use serde_json::Value;
use sso_ory_client::{error::OryClientError, kratos::KratosClient};
use tracing::warn;

use crate::db::{
    SamlIdpKeyRepo, SamlIdpKeyStore, SamlNameIdMappingStore, SamlRequestStore, SamlSpClientRepo,
    SamlSpClientStore, compute_pairwise_name_id,
};

const HTML_CONTENT_TYPE: &str = "text/html";

#[derive(Debug)]
enum SamlIdpError {
    Response(Box<Response<Body>>),
}

impl IntoResponse for SamlIdpError {
    fn into_response(self) -> Response<Body> {
        match self {
            SamlIdpError::Response(resp) => *resp,
        }
    }
}

impl From<crate::db::DbError> for SamlIdpError {
    fn from(err: crate::db::DbError) -> Self {
        let status = match err {
            crate::db::DbError::SamlSpClientNotFound => StatusCode::NOT_FOUND,
            crate::db::DbError::SamlIdpKeyNotFound => StatusCode::NOT_FOUND,
            crate::db::DbError::SamlRequestReplay => StatusCode::BAD_REQUEST,
            _ => {
                warn!("saml idp db error: {}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        Self::Response(Box::new(idp_error(status, "idp request unavailable")))
    }
}

impl From<sso_ory_client::error::OryClientError> for SamlIdpError {
    fn from(err: sso_ory_client::error::OryClientError) -> Self {
        let status = match err {
            sso_ory_client::error::OryClientError::Ory {
                status: 401 | 403, ..
            } => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self::Response(Box::new(idp_error(status, "session invalid")))
    }
}

impl From<sunbeam_g2v::error::ServiceError> for SamlIdpError {
    fn from(err: sunbeam_g2v::error::ServiceError) -> Self {
        warn!("saml idp service error: {}", err);
        Self::Response(Box::new(idp_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "idp request unavailable",
        )))
    }
}

/// Async trait for the Kratos operation used by the SAML IdP HTTP handler.
#[async_trait]
pub trait SamlIdpKratos: Send + Sync + 'static {
    async fn whoami(&self, session_token: &str) -> Result<Value, OryClientError>;
}

#[async_trait]
impl SamlIdpKratos for KratosClient {
    async fn whoami(&self, session_token: &str) -> Result<Value, OryClientError> {
        self.whoami(session_token).await
    }
}

const DEFAULT_REQUEST_TTL: Duration = Duration::from_secs(900);

#[derive(Clone)]
pub struct SamlIdpState {
    pub(crate) kratos: Arc<dyn SamlIdpKratos>,
    pub(crate) idp_keys: Arc<dyn SamlIdpKeyStore>,
    pub(crate) sp_clients: Arc<dyn SamlSpClientStore>,
    pub(crate) requests: Option<Arc<dyn SamlRequestStore>>,
    pub(crate) nameid_mappings: Option<Arc<dyn SamlNameIdMappingStore>>,
    pub(crate) idp_entity_id: String,
    pub(crate) sso_endpoint_url: String,
    pub(crate) request_ttl: Duration,
}

impl SamlIdpState {
    pub fn new(
        kratos: Arc<KratosClient>,
        idp_keys: SamlIdpKeyRepo,
        sp_clients: SamlSpClientRepo,
        idp_entity_id: String,
    ) -> Self {
        let sso_endpoint_url = format!("{}/saml/sso", idp_entity_id.trim_end_matches('/'));
        Self {
            kratos: kratos as Arc<dyn SamlIdpKratos>,
            idp_keys: Arc::new(idp_keys) as Arc<dyn SamlIdpKeyStore>,
            sp_clients: Arc::new(sp_clients) as Arc<dyn SamlSpClientStore>,
            requests: None,
            nameid_mappings: None,
            idp_entity_id,
            sso_endpoint_url,
            request_ttl: DEFAULT_REQUEST_TTL,
        }
    }

    pub fn with_request_store(mut self, requests: crate::db::SamlRequestRepo) -> Self {
        self.requests = Some(Arc::new(requests) as Arc<dyn SamlRequestStore>);
        self
    }

    pub fn with_nameid_mappings(
        mut self,
        nameid_mappings: crate::db::SamlNameIdMappingRepo,
    ) -> Self {
        self.nameid_mappings = Some(Arc::new(nameid_mappings) as Arc<dyn SamlNameIdMappingStore>);
        self
    }

    pub fn with_sso_endpoint_url(mut self, url: String) -> Self {
        self.sso_endpoint_url = url;
        self
    }
}

pub fn router(state: Arc<SamlIdpState>) -> Router {
    Router::new().route("/saml/sso", get(sso)).with_state(state)
}

#[derive(Debug)]
struct RedirectRequest<'a> {
    url: &'a str,
    params: HashMap<String, String>,
}

impl<'a> RedirectRequest<'a> {
    fn from_url(url: &'a str) -> Self {
        let params = match url.split_once('?') {
            Some((_, query)) => parse_query_params(query),
            None => HashMap::new(),
        };
        Self { url, params }
    }
}

impl HttpRequest for RedirectRequest<'_> {
    fn method(&self) -> &str {
        "GET"
    }

    fn url(&self) -> &str {
        self.url
    }

    fn query_param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(|s| s.as_str())
    }

    fn form_param(&self, _name: &str) -> Option<&str> {
        None
    }

    fn header(&self, _name: &str) -> Option<&str> {
        None
    }

    fn body(&self) -> &[u8] {
        &[]
    }

    fn remote_addr(&self) -> Option<&str> {
        None
    }
}

fn parse_query_params(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = match parts.next() {
                Some(v) => v.to_owned(),
                None => String::new(),
            };
            Some((key.to_string(), value))
        })
        .collect()
}

fn extract_session_token(req: &Request<Body>) -> Result<&str, SamlIdpError> {
    req.headers()
        .get("X-Session-Token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            SamlIdpError::Response(Box::new(idp_error(
                StatusCode::UNAUTHORIZED,
                "missing session",
            )))
        })
}

async fn sso(
    State(state): State<Arc<SamlIdpState>>,
    Query(query): Query<HashMap<String, String>>,
    req: Request<Body>,
) -> Result<Response<Body>, SamlIdpError> {
    let provider_id = query.get("provider_id").ok_or_else(|| {
        SamlIdpError::Response(Box::new(idp_error(
            StatusCode::BAD_REQUEST,
            "missing provider_id",
        )))
    })?;

    let url = req.uri().to_string();
    let redirect_req = RedirectRequest::from_url(&url);
    let decoded = redirect_decode(&redirect_req).map_err(|e| {
        warn!("saml idp redirect decode error: {e}");
        SamlIdpError::Response(Box::new(idp_error(
            StatusCode::BAD_REQUEST,
            "invalid saml request",
        )))
    })?;

    let saml_xml = String::from_utf8(decoded.saml_xml.clone()).map_err(|e| {
        warn!("saml idp request encoding error: {e}");
        SamlIdpError::Response(Box::new(idp_error(
            StatusCode::BAD_REQUEST,
            "invalid saml request",
        )))
    })?;

    let doc = parse_secure(&saml_xml).map_err(|e| {
        warn!("saml idp parse error: {e}");
        SamlIdpError::Response(Box::new(idp_error(
            StatusCode::BAD_REQUEST,
            "invalid saml request",
        )))
    })?;
    let authn_request: AuthnRequest = parse_saml::<AuthnRequestRef>(&doc)
        .map_err(|e| {
            warn!("saml idp request validation error: {e}");
            SamlIdpError::Response(Box::new(idp_error(
                StatusCode::BAD_REQUEST,
                "invalid saml request",
            )))
        })?
        .to_owned();

    let sp_client = state.sp_clients.get_by_id(provider_id).await?;

    if let Some(issuer) = &authn_request.base.issuer
        && issuer.value != sp_client.entity_id
    {
        return Err(SamlIdpError::Response(Box::new(idp_error(
            StatusCode::BAD_REQUEST,
            "issuer mismatch",
        ))));
    }

    let Some(destination) = authn_request.base.destination.as_ref() else {
        return Err(SamlIdpError::Response(Box::new(idp_error(
            StatusCode::BAD_REQUEST,
            "missing saml destination",
        ))));
    };
    if destination != &state.sso_endpoint_url {
        return Err(SamlIdpError::Response(Box::new(idp_error(
            StatusCode::BAD_REQUEST,
            "destination mismatch",
        ))));
    }

    if sp_client.authn_requests_signed {
        if decoded.signature.is_none() {
            return Err(SamlIdpError::Response(Box::new(idp_error(
                StatusCode::BAD_REQUEST,
                "signed authn request required",
            ))));
        }
        let Some(cert_pem) = sp_client.certificate_pem.as_deref() else {
            return Err(SamlIdpError::Response(Box::new(idp_error(
                StatusCode::BAD_REQUEST,
                "signed authn request required but no sp certificate configured",
            ))));
        };
        let mut keys_manager = gamlastan::crypto::keys::bergshamra_keys::KeysManager::new();
        let mut loaded = false;
        for cert_block in split_certificate_pem_blocks(cert_pem) {
            match gamlastan::crypto::keys::loader::load_x509_cert_pem(cert_block.as_bytes()) {
                Ok(key) => {
                    keys_manager.add_key(key);
                    loaded = true;
                }
                Err(_) => continue,
            }
        }
        if !loaded {
            return Err(SamlIdpError::Response(Box::new(idp_error(
                StatusCode::BAD_REQUEST,
                "no loadable sp certificate",
            ))));
        }
        let verifier = SamlVerifier::new(keys_manager);
        let valid = redirect_verify_signature(&decoded, &verifier).map_err(|e| {
            warn!("saml idp signature verification error: {e}");
            SamlIdpError::Response(Box::new(idp_error(
                StatusCode::BAD_REQUEST,
                "invalid authn request signature",
            )))
        })?;
        if !valid {
            return Err(SamlIdpError::Response(Box::new(idp_error(
                StatusCode::BAD_REQUEST,
                "invalid authn request signature",
            ))));
        }
    }

    // Persist the inbound request ID to reject replays.
    if let Some(requests) = &state.requests {
        requests
            .create_inbound(
                &sp_client.tenant_id,
                &sp_client.id,
                &authn_request.base.id,
                state.request_ttl,
            )
            .await?;
    }

    if authn_request.force_authn == Some(true) {
        return Err(SamlIdpError::Response(Box::new(idp_error(
            StatusCode::UNAUTHORIZED,
            "fresh authentication required",
        ))));
    }

    let session_token = extract_session_token(&req)?;

    let session = state.kratos.whoami(session_token).await?;
    let identity = session.get("identity").ok_or_else(|| {
        SamlIdpError::Response(Box::new(idp_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session missing identity",
        )))
    })?;
    let identity_id = identity.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
        SamlIdpError::Response(Box::new(idp_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session missing identity id",
        )))
    })?;
    let email = match identity
        .get("traits")
        .and_then(|t| t.get("email"))
        .and_then(|v| v.as_str())
    {
        Some(email) => email,
        None => identity_id,
    };

    let idp_key = state.idp_keys.get_active(&sp_client.tenant_id).await?;
    let mut key_manager =
        build_idp_keys_manager(idp_key.private_key_pem.as_bytes()).map_err(|e| {
            warn!("saml idp signing key error: {e}");
            SamlIdpError::Response(Box::new(idp_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "idp request unavailable",
            )))
        })?;
    key_manager.add_trusted_cert(idp_key.certificate_pem.into_bytes());
    let signer = SamlSigner::new(key_manager);

    let name_id_value = resolve_pairwise_name_id(
        state.nameid_mappings.as_ref(),
        &sp_client.tenant_id,
        &sp_client.entity_id,
        identity_id,
    )
    .await;
    let authn_context_class_ref = authn_context_class_from_session(&session);

    let options = ResponseOptions {
        idp_entity_id: state.idp_entity_id.clone(),
        in_response_to: Some(authn_request.base.id.clone()),
        sp_entity_id: sp_client.entity_id.clone(),
        acs_url: sp_client.acs_url.clone(),
        assertion_lifetime_seconds: 300,
        session_index: Some(name_id_value.clone()),
        session_not_on_or_after: None,
        authn_context_class_ref: Some(authn_context_class_ref),
        client_address: None,
        attributes: vec![Attribute {
            name: "email".to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![AttributeValue::String(email.to_string())],
        }],
    };
    let name_id = NameId {
        value: name_id_value,
        format: Some(constants::NAMEID_PERSISTENT.to_string()),
        name_qualifier: None,
        sp_name_qualifier: None,
        sp_provided_id: None,
    };
    let response = create_response(&options, &name_id, ResponseTimes::at(Utc::now()));
    let response_xml = response.to_xml_string().map_err(|e| {
        warn!("saml idp response serialization error: {e}");
        SamlIdpError::Response(Box::new(idp_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "idp request unavailable",
        )))
    })?;
    let response_id = response.base.id.clone();
    let status_pos = response_xml.find("<samlp:Status").ok_or_else(|| {
        SamlIdpError::Response(Box::new(idp_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "response missing status element",
        )))
    })?;
    let mut xml_with_signature = response_xml;
    xml_with_signature.insert_str(status_pos, &response_signature_template(&response_id));
    let signed_xml = signer.sign_enveloped(&xml_with_signature).map_err(|e| {
        warn!("saml idp response signing error: {e}");
        SamlIdpError::Response(Box::new(idp_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "idp request unavailable",
        )))
    })?;

    let saml_response_b64 = base64::engine::general_purpose::STANDARD.encode(signed_xml.as_bytes());
    let relay_state = match decoded.relay_state.as_deref() {
        Some(state) => state.to_owned(),
        None => String::new(),
    };
    let html = format!(
        r#"<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form method="post" action="{}">
<input type="hidden" name="SAMLResponse" value="{}"/>
<input type="hidden" name="RelayState" value="{}"/>
<noscript><button type="submit">Continue</button></noscript>
</form></body></html>"#,
        html_escape(&sp_client.acs_url),
        html_escape(&saml_response_b64),
        html_escape(&relay_state)
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, HTML_CONTENT_TYPE)
        .body(Body::from(html))
        .map_err(|e| {
            warn!("saml idp response builder error: {e}");
            SamlIdpError::Response(Box::new(idp_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "idp request unavailable",
            )))
        })
}

fn response_signature_template(response_id: &str) -> String {
    format!(
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
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('\'', "&#x27;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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

/// Derive a SAML authentication context class reference from the Kratos
/// session's `authentication_methods` array. Falls back to the password
/// context when no methods are present.
fn authn_context_class_from_session(session: &Value) -> String {
    let methods = match session
        .get("authentication_methods")
        .and_then(|v| v.as_array())
    {
        Some(arr) => arr.clone(),
        None => Vec::new(),
    };

    let mut has_webauthn = false;
    let mut has_totp = false;
    let mut has_password = false;
    for method in &methods {
        if let Some(name) = method.get("method").and_then(|v| v.as_str()) {
            match name {
                "webauthn" => has_webauthn = true,
                "totp" => has_totp = true,
                "password" => has_password = true,
                _ => {}
            }
        }
    }

    if has_webauthn {
        // SAML 2.0 has no dedicated WebAuthn context class; the strongest
        // standard class for an authenticated TLS session is used.
        constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT.to_string()
    } else if has_totp {
        "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken".to_string()
    } else if has_password {
        constants::AUTHN_CONTEXT_PASSWORD.to_string()
    } else {
        constants::AUTHN_CONTEXT_UNSPECIFIED.to_string()
    }
}

async fn resolve_pairwise_name_id(
    nameid_mappings: Option<&Arc<dyn SamlNameIdMappingStore>>,
    tenant_id: &str,
    sp_entity_id: &str,
    identity_id: &str,
) -> String {
    if let Some(store) = nameid_mappings {
        match store
            .get_or_create(tenant_id, sp_entity_id, identity_id)
            .await
        {
            Ok(name_id) => name_id,
            Err(e) => {
                warn!("saml nameid mapping lookup failed: {e}; falling back to computed nameid");
                compute_pairwise_name_id(tenant_id, sp_entity_id, identity_id)
            }
        }
    } else {
        compute_pairwise_name_id(tenant_id, sp_entity_id, identity_id)
    }
}

fn idp_error(status: StatusCode, detail: &str) -> Response<Body> {
    let body = Body::from(format!("{{\"error\":\"{detail}\"}}"));
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use http_body_util::BodyExt;
    use std::sync::Mutex;

    use crate::db::{DbError, SamlIdpKeyRow, SamlSpClientRow};
    use gamlastan::bindings::redirect::{RedirectEncodeParams, redirect_encode};
    use gamlastan::bindings::relay_state::RelayState;
    use gamlastan::core::assertion::issuer::Issuer;
    use gamlastan::core::identifiers::SamlVersion;
    use gamlastan::core::protocol::request::{AuthnRequest, RequestBase};
    use serde_json::json;

    #[derive(Clone, Default)]
    struct StubKratos;

    #[async_trait]
    impl SamlIdpKratos for StubKratos {
        async fn whoami(&self, _session_token: &str) -> Result<Value, OryClientError> {
            unimplemented!("stub whoami not configured")
        }
    }

    #[derive(Clone, Default)]
    struct StubIdpKeyStore;

    #[async_trait]
    impl SamlIdpKeyStore for StubIdpKeyStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _key_id: &str,
            _private_key_pem: &str,
            _certificate_pem: &str,
            _is_active: bool,
        ) -> Result<crate::db::SamlIdpKeyRow, crate::db::DbError> {
            unimplemented!()
        }

        async fn get_active(
            &self,
            _tenant_id: &str,
        ) -> Result<crate::db::SamlIdpKeyRow, crate::db::DbError> {
            unimplemented!()
        }

        async fn list(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<crate::db::SamlIdpKeyRow>, crate::db::DbError> {
            unimplemented!()
        }
    }

    #[derive(Clone, Default)]
    struct StubSpClientStore {
        client: Arc<Mutex<Option<Result<SamlSpClientRow, crate::db::DbError>>>>,
    }

    #[async_trait]
    impl SamlSpClientStore for StubSpClientStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _entity_id: &str,
            _acs_url: &str,
            _certificate_pem: Option<&str>,
            _authn_requests_signed: bool,
            _name_id_format: Option<&str>,
        ) -> Result<SamlSpClientRow, crate::db::DbError> {
            unimplemented!()
        }

        async fn get(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<SamlSpClientRow, crate::db::DbError> {
            unimplemented!()
        }

        async fn get_by_id(&self, _id: &str) -> Result<SamlSpClientRow, crate::db::DbError> {
            self.client
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn get_by_entity_id(
            &self,
            _tenant_id: &str,
            _entity_id: &str,
        ) -> Result<SamlSpClientRow, crate::db::DbError> {
            unimplemented!()
        }
    }

    fn test_sp_client(entity_id: &str) -> SamlSpClientRow {
        SamlSpClientRow {
            id: "sp-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            entity_id: entity_id.to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            certificate_pem: None,
            authn_requests_signed: false,
            name_id_format: None,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn test_state(
        client: Option<Result<SamlSpClientRow, crate::db::DbError>>,
    ) -> Arc<SamlIdpState> {
        Arc::new(SamlIdpState {
            kratos: Arc::new(StubKratos),
            idp_keys: Arc::new(StubIdpKeyStore),
            sp_clients: Arc::new(StubSpClientStore {
                client: Arc::new(Mutex::new(client)),
            }),
            requests: None,
            nameid_mappings: None,
            idp_entity_id: "https://idp.example.com".to_string(),
            sso_endpoint_url: "https://idp.example.com/saml/sso".to_string(),
            request_ttl: DEFAULT_REQUEST_TTL,
        })
    }

    #[derive(Clone, Default)]
    struct StubNameIdMappingStore;

    #[async_trait]
    impl SamlNameIdMappingStore for StubNameIdMappingStore {
        async fn get_or_create(
            &self,
            tenant_id: &str,
            sp_entity_id: &str,
            identity_id: &str,
        ) -> Result<String, DbError> {
            Ok(compute_pairwise_name_id(
                tenant_id,
                sp_entity_id,
                identity_id,
            ))
        }

        async fn find_by_name_id(
            &self,
            _tenant_id: &str,
            _sp_entity_id: &str,
            name_id: &str,
        ) -> Result<String, DbError> {
            Ok(name_id.to_string())
        }
    }

    #[derive(Clone, Default)]
    struct ConfigurableKratos {
        result: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
    }

    #[async_trait]
    impl SamlIdpKratos for ConfigurableKratos {
        async fn whoami(&self, _session_token: &str) -> Result<Value, OryClientError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .expect("kratos stub not configured")
        }
    }

    #[derive(Clone, Default)]
    struct ConfigurableIdpKeyStore {
        result: Arc<Mutex<Option<Result<SamlIdpKeyRow, crate::db::DbError>>>>,
    }

    #[async_trait]
    impl SamlIdpKeyStore for ConfigurableIdpKeyStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _key_id: &str,
            _private_key_pem: &str,
            _certificate_pem: &str,
            _is_active: bool,
        ) -> Result<SamlIdpKeyRow, crate::db::DbError> {
            unimplemented!()
        }

        async fn get_active(&self, _tenant_id: &str) -> Result<SamlIdpKeyRow, crate::db::DbError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .expect("idp key stub not configured")
        }

        async fn list(&self, _tenant_id: &str) -> Result<Vec<SamlIdpKeyRow>, crate::db::DbError> {
            unimplemented!()
        }
    }

    fn test_state_full(
        client: Option<Result<SamlSpClientRow, crate::db::DbError>>,
        kratos: Option<Result<Value, OryClientError>>,
        idp_key: Option<Result<SamlIdpKeyRow, crate::db::DbError>>,
    ) -> Arc<SamlIdpState> {
        Arc::new(SamlIdpState {
            kratos: Arc::new(ConfigurableKratos {
                result: Arc::new(Mutex::new(kratos)),
            }),
            idp_keys: Arc::new(ConfigurableIdpKeyStore {
                result: Arc::new(Mutex::new(idp_key)),
            }),
            sp_clients: Arc::new(StubSpClientStore {
                client: Arc::new(Mutex::new(client)),
            }),
            requests: None,
            nameid_mappings: Some(Arc::new(StubNameIdMappingStore)),
            idp_entity_id: "https://idp.example.com".to_string(),
            sso_endpoint_url: "https://idp.example.com/saml/sso".to_string(),
            request_ttl: DEFAULT_REQUEST_TTL,
        })
    }

    fn active_idp_key() -> SamlIdpKeyRow {
        SamlIdpKeyRow {
            id: "key-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            key_id: "default".to_string(),
            private_key_pem: std::str::from_utf8(include_bytes!(
                "../../../tests/fixtures/saml-test-key.pem"
            ))
            .unwrap()
            .to_string(),
            certificate_pem: std::str::from_utf8(include_bytes!(
                "../../../tests/fixtures/saml-test-cert.pem"
            ))
            .unwrap()
            .to_string(),
            is_active: true,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn session_with_email(email: &str) -> Value {
        json!({"identity": {"id": "identity-1", "traits": {"email": email}}})
    }

    fn authn_request_url(
        entity_id: &str,
        provider_id: &str,
        signer_key_pem: Option<&[u8]>,
    ) -> String {
        let destination = format!("/saml/sso?provider_id={provider_id}");
        let authn_request = AuthnRequest {
            base: RequestBase {
                id: "_req_123".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: Some("https://idp.example.com/saml/sso".to_string()),
                consent: None,
                issuer: Some(Issuer::entity(entity_id)),
                has_signature: false,
            },
            subject: None,
            name_id_policy: None,
            conditions: None,
            requested_authn_context: None,
            scoping: None,
            force_authn: None,
            is_passive: None,
            assertion_consumer_service_index: None,
            assertion_consumer_service_url: Some("https://sp.example.com/acs".to_string()),
            protocol_binding: None,
            attribute_consuming_service_index: None,
            provider_name: None,
            extensions: None,
        };
        let saml_xml = authn_request
            .to_xml_string()
            .expect("serialize authn request");
        let signer_key_pem =
            signer_key_pem.unwrap_or(include_bytes!("../../../tests/fixtures/saml-test-key.pem"));
        let key_manager = build_idp_keys_manager(signer_key_pem).expect("load signer key");
        let signer = SamlSigner::new(key_manager);
        let signer_ref = Some((&signer, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"));
        let relay_state = RelayState::new("state").ok();
        let params = RedirectEncodeParams {
            saml_xml: saml_xml.as_bytes(),
            is_request: true,
            destination: &destination,
            relay_state: relay_state.as_ref(),
            signer: signer_ref,
        };
        redirect_encode(&params).expect("encode authn request")
    }

    fn unsigned_authn_request_url(entity_id: &str, provider_id: &str) -> String {
        let destination = format!("/saml/sso?provider_id={provider_id}");
        let authn_request = AuthnRequest {
            base: RequestBase {
                id: "_req_123".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: Some("https://idp.example.com/saml/sso".to_string()),
                consent: None,
                issuer: Some(Issuer::entity(entity_id)),
                has_signature: false,
            },
            subject: None,
            name_id_policy: None,
            conditions: None,
            requested_authn_context: None,
            scoping: None,
            force_authn: None,
            is_passive: None,
            assertion_consumer_service_index: None,
            assertion_consumer_service_url: Some("https://sp.example.com/acs".to_string()),
            protocol_binding: None,
            attribute_consuming_service_index: None,
            provider_name: None,
            extensions: None,
        };
        let saml_xml = authn_request
            .to_xml_string()
            .expect("serialize authn request");
        let params = RedirectEncodeParams {
            saml_xml: saml_xml.as_bytes(),
            is_request: true,
            destination: &destination,
            relay_state: None,
            signer: None,
        };
        redirect_encode(&params).expect("encode unsigned authn request")
    }

    fn authn_request_url_with_destination(
        entity_id: &str,
        provider_id: &str,
        destination: Option<String>,
        signer_key_pem: Option<&[u8]>,
    ) -> String {
        let query_destination = format!("/saml/sso?provider_id={provider_id}");
        let authn_request = AuthnRequest {
            base: RequestBase {
                id: "_req_123".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination,
                consent: None,
                issuer: Some(Issuer::entity(entity_id)),
                has_signature: false,
            },
            subject: None,
            name_id_policy: None,
            conditions: None,
            requested_authn_context: None,
            scoping: None,
            force_authn: None,
            is_passive: None,
            assertion_consumer_service_index: None,
            assertion_consumer_service_url: Some("https://sp.example.com/acs".to_string()),
            protocol_binding: None,
            attribute_consuming_service_index: None,
            provider_name: None,
            extensions: None,
        };
        let saml_xml = authn_request
            .to_xml_string()
            .expect("serialize authn request");
        let signer_key_pem =
            signer_key_pem.unwrap_or(include_bytes!("../../../tests/fixtures/saml-test-key.pem"));
        let key_manager = build_idp_keys_manager(signer_key_pem).expect("load signer key");
        let signer = SamlSigner::new(key_manager);
        let signer_ref = Some((&signer, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"));
        let params = RedirectEncodeParams {
            saml_xml: saml_xml.as_bytes(),
            is_request: true,
            destination: &query_destination,
            relay_state: None,
            signer: signer_ref,
        };
        redirect_encode(&params).expect("encode authn request")
    }

    fn sso_request(uri: &str, headers: Vec<(&str, &str)>) -> Request<Body> {
        let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        for (k, v) in headers {
            let name = k.parse::<axum::http::HeaderName>().unwrap();
            let value = HeaderValue::from_str(v).unwrap();
            req.headers_mut().insert(name, value);
        }
        req
    }

    async fn body_to_string(resp: Response<Body>) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn idp_error_builds_json_response() {
        let resp = idp_error(StatusCode::BAD_REQUEST, "missing provider_id");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn idp_error_body_contains_detail() {
        let resp = idp_error(StatusCode::UNAUTHORIZED, "missing session");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("missing session"));
    }

    #[test]
    fn saml_idp_error_from_db_error_maps_sp_client_not_found() {
        let err: SamlIdpError = crate::db::DbError::SamlSpClientNotFound.into();
        assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn saml_idp_error_from_db_error_maps_idp_key_not_found() {
        let err: SamlIdpError = crate::db::DbError::SamlIdpKeyNotFound.into();
        assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn saml_idp_error_from_db_error_maps_other_to_internal() {
        let err: SamlIdpError = crate::db::DbError::Sqlx(sqlx::Error::PoolTimedOut).into();
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn saml_idp_error_from_ory_error_maps_unauthorized() {
        let err: SamlIdpError = sso_ory_client::error::OryClientError::Ory {
            status: 401,
            message: "unauth".into(),
        }
        .into();
        assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn saml_idp_error_from_ory_error_maps_other_to_internal() {
        let err: SamlIdpError = sso_ory_client::error::OryClientError::Ory {
            status: 500,
            message: "down".into(),
        }
        .into();
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn saml_idp_error_from_service_error_maps_internal() {
        let err: SamlIdpError = sunbeam_g2v::error::ServiceError::Internal("fail".into()).into();
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn html_escape_escapes_special_characters() {
        assert_eq!(
            html_escape("<script>alert(\"x\");</script>"),
            "&lt;script&gt;alert(&quot;x&quot;);&lt;/script&gt;"
        );
    }

    #[test]
    fn split_certificate_pem_blocks_extracts_multiple() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----";
        let blocks = split_certificate_pem_blocks(pem);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("MIIB"));
        assert!(blocks[1].contains("MIIC"));
    }

    #[test]
    fn split_certificate_pem_blocks_returns_empty_for_invalid() {
        assert!(split_certificate_pem_blocks("not a pem").is_empty());
    }

    #[test]
    fn parse_query_params_extracts_key_values() {
        let params = parse_query_params("a=1&b=2&c=3=4");
        assert_eq!(params.get("a"), Some(&"1".to_string()));
        assert_eq!(params.get("b"), Some(&"2".to_string()));
        assert_eq!(params.get("c"), Some(&"3=4".to_string()));
    }

    #[test]
    fn redirect_request_parses_url() {
        let req = RedirectRequest::from_url("/saml/sso?SAMLRequest=abc&RelayState=xyz");
        assert_eq!(req.method(), "GET");
        assert_eq!(req.url(), "/saml/sso?SAMLRequest=abc&RelayState=xyz");
        assert_eq!(req.query_param("SAMLRequest"), Some("abc"));
        assert_eq!(req.query_param("RelayState"), Some("xyz"));
        assert_eq!(req.query_param("Missing"), None);
    }

    #[test]
    fn redirect_request_without_query_has_empty_params() {
        let req = RedirectRequest::from_url("/saml/sso");
        assert_eq!(req.method(), "GET");
        assert_eq!(req.url(), "/saml/sso");
        assert_eq!(req.query_param("SAMLRequest"), None);
        assert!(req.params.is_empty());
    }

    #[test]
    fn redirect_request_handles_malformed_query() {
        // Missing value for a key and an empty pair are tolerated by the parser.
        let req = RedirectRequest::from_url("/saml/sso?SAMLRequest&=x&RelayState=abc");
        assert_eq!(req.query_param("SAMLRequest"), Some(""));
        assert_eq!(req.query_param("RelayState"), Some("abc"));
    }

    #[test]
    fn response_signature_template_contains_reference() {
        let tpl = response_signature_template("_response_1");
        assert!(tpl.contains("URI=\"#_response_1\""));
        assert!(tpl.contains("rsa-sha256"));
    }

    #[test]
    fn extract_session_token_returns_token_when_present() {
        let req = sso_request("/saml/sso", vec![("X-Session-Token", "session-1")]);
        assert_eq!(extract_session_token(&req).unwrap(), "session-1");
    }

    #[test]
    fn extract_session_token_returns_unauthorized_when_missing() {
        let req = sso_request("/saml/sso", vec![]);
        let err = extract_session_token(&req).unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn extract_session_token_returns_unauthorized_when_invalid_utf8() {
        let mut req = Request::builder()
            .uri("/saml/sso")
            .body(Body::empty())
            .unwrap();
        req.headers_mut()
            .insert("X-Session-Token", HeaderValue::from_bytes(b"\xff").unwrap());
        let err = extract_session_token(&req).unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sso_returns_bad_request_when_provider_id_missing() {
        let state = test_state(None);
        let req = sso_request("/saml/sso", vec![]);
        let resp = sso(State(state), Query(HashMap::new()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing provider_id"));
    }

    #[tokio::test]
    async fn sso_returns_bad_request_when_redirect_decode_fails() {
        let state = test_state(Some(Ok(test_sp_client("https://sp.example.com"))));
        let mut params = HashMap::new();
        params.insert("provider_id".to_string(), "sp-1".to_string());
        let req = sso_request(
            "/saml/sso?SAMLRequest=not-valid-base64&&RelayState=rs",
            vec![],
        );
        let resp = sso(State(state), Query(params), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("invalid saml request"));
    }

    fn provider_query() -> HashMap<String, String> {
        HashMap::from([("provider_id".to_string(), "sp-1".to_string())])
    }

    #[tokio::test]
    async fn sso_returns_signed_saml_response_html() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .expect("sso should succeed");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            HTML_CONTENT_TYPE
        );
        let body = body_to_string(resp).await;
        assert!(body.contains("SAMLResponse"));
        assert!(body.contains("https://sp.example.com/acs"));
    }

    #[tokio::test]
    async fn sso_rejects_issuer_mismatch() {
        let url = authn_request_url("https://other-sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("issuer mismatch"));
    }

    #[tokio::test]
    async fn sso_rejects_missing_destination() {
        let url = authn_request_url_with_destination("https://sp.example.com", "sp-1", None, None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing saml destination"));
    }

    #[tokio::test]
    async fn sso_rejects_destination_mismatch() {
        let url = authn_request_url_with_destination(
            "https://sp.example.com",
            "sp-1",
            Some("https://other-idp.example.com/saml/sso".to_string()),
            None,
        );
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("destination mismatch"));
    }

    #[tokio::test]
    async fn sso_rejects_signed_request_when_sp_has_no_certificate() {
        let url = authn_request_url(
            "https://sp.example.com",
            "sp-1",
            Some(include_bytes!("../../../tests/fixtures/saml-test-key.pem")),
        );
        let mut client = test_sp_client("https://sp.example.com");
        client.authn_requests_signed = true;
        client.certificate_pem = None;
        let state = test_state_full(
            Some(Ok(client)),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("signed authn request required but no sp certificate configured"));
    }

    #[tokio::test]
    async fn sso_rejects_invalid_authn_request_signature() {
        // Sign with a different key than the SP certificate configured in the store.
        let url = authn_request_url(
            "https://sp.example.com",
            "sp-1",
            Some(include_bytes!("../../../tests/fixtures/saml-other-key.pem")),
        );
        let cert_pem =
            std::str::from_utf8(include_bytes!("../../../tests/fixtures/saml-test-cert.pem"))
                .unwrap()
                .to_string();
        let mut client = test_sp_client("https://sp.example.com");
        client.authn_requests_signed = true;
        client.certificate_pem = Some(cert_pem);
        let state = test_state_full(
            Some(Ok(client)),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("invalid authn request signature"));
    }

    #[tokio::test]
    async fn sso_rejects_missing_session_token() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sso_rejects_session_without_identity() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(json!({}))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_to_string(resp).await;
        assert!(body.contains("session missing identity"));
    }

    #[tokio::test]
    async fn sso_rejects_session_without_identity_id() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(
                json!({"identity": {"traits": {"email": "alice@example.com"}}}),
            )),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_to_string(resp).await;
        assert!(body.contains("session missing identity id"));
    }

    #[tokio::test]
    async fn sso_returns_not_found_when_idp_key_missing() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Err(crate::db::DbError::SamlIdpKeyNotFound)),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn sso_returns_internal_error_when_idp_key_is_invalid() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let bad_key = SamlIdpKeyRow {
            private_key_pem: "not a valid key".to_string(),
            ..active_idp_key()
        };
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(bad_key)),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn sso_returns_internal_error_when_idp_key_store_fails() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Err(crate::db::DbError::Sqlx(sqlx::Error::PoolTimedOut))),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn sso_rejects_malformed_saml_payload_after_decode() {
        let saml_xml = "<root/>";
        let destination = "/saml/sso?provider_id=sp-1";
        let params = RedirectEncodeParams {
            saml_xml: saml_xml.as_bytes(),
            is_request: true,
            destination,
            relay_state: None,
            signer: None,
        };
        let url = redirect_encode(&params).expect("encode custom xml");
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            None,
            None,
        );
        let req = sso_request(&url, vec![]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("invalid saml request"));
    }

    #[tokio::test]
    async fn sso_rejects_unsigned_request() {
        let url = unsigned_authn_request_url("https://sp.example.com", "sp-1");
        let cert_pem =
            std::str::from_utf8(include_bytes!("../../../tests/fixtures/saml-test-cert.pem"))
                .unwrap()
                .to_string();
        let mut client = test_sp_client("https://sp.example.com");
        client.authn_requests_signed = true;
        client.certificate_pem = Some(cert_pem);
        let state = test_state_full(
            Some(Ok(client)),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("signed authn request required"));
    }

    #[test]
    fn redirect_request_http_request_trait_returns_defaults() {
        let req = RedirectRequest::from_url("/saml/sso?a=1");
        assert_eq!(req.form_param("x"), None);
        assert_eq!(req.header("x"), None);
        assert!(req.body().is_empty());
        assert_eq!(req.remote_addr(), None);
    }

    #[tokio::test]
    async fn saml_idp_state_new_stores_dependencies() {
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost:5432/unused").unwrap();
        let kratos = Arc::new(
            sso_ory_client::kratos::KratosClient::new_with_public("http://admin", "http://public")
                .unwrap(),
        );
        let idp_keys = SamlIdpKeyRepo::new(pool.clone());
        let sp_clients = SamlSpClientRepo::new(pool);
        let state = SamlIdpState::new(
            kratos,
            idp_keys,
            sp_clients,
            "https://idp.example.com".to_string(),
        );
        assert_eq!(state.idp_entity_id, "https://idp.example.com");
    }

    #[tokio::test]
    async fn sso_returns_not_found_when_sp_client_missing() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Err(crate::db::DbError::SamlSpClientNotFound)),
            None,
            None,
        );
        let req = sso_request(&url, vec![]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn sso_returns_bad_request_for_invalid_utf8_saml_xml() {
        let destination = "/saml/sso?provider_id=sp-1";
        let params = RedirectEncodeParams {
            saml_xml: &[0x80, 0x81, 0x82],
            is_request: true,
            destination,
            relay_state: None,
            signer: None,
        };
        let url = redirect_encode(&params).expect("encode invalid bytes");
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            None,
            None,
        );
        let req = sso_request(&url, vec![]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("invalid saml request"));
    }

    #[tokio::test]
    async fn sso_returns_bad_request_for_non_saml_xml() {
        let destination = "/saml/sso?provider_id=sp-1";
        let params = RedirectEncodeParams {
            saml_xml: "<not-a-saml-request/>".as_bytes(),
            is_request: true,
            destination,
            relay_state: None,
            signer: None,
        };
        let url = redirect_encode(&params).expect("encode custom xml");
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            None,
            None,
        );
        let req = sso_request(&url, vec![]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("invalid saml request"));
    }

    #[tokio::test]
    async fn sso_returns_unauthorized_when_kratos_session_invalid() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Err(OryClientError::Ory {
                status: 401,
                message: "no session".into(),
            })),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "bad-token")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sso_returns_internal_error_when_kratos_returns_forbidden() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Err(OryClientError::Ory {
                status: 403,
                message: "forbidden".into(),
            })),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "bad-token")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sso_returns_internal_error_for_non_ory_kratos_error() {
        let url = authn_request_url("https://sp.example.com", "sp-1", None);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Err(OryClientError::Http(
                reqwest::get("http://localhost:1").await.unwrap_err(),
            ))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "bad-token")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    fn authn_request_url_with_force_authn(
        entity_id: &str,
        provider_id: &str,
        force_authn: bool,
    ) -> String {
        let destination = format!("/saml/sso?provider_id={provider_id}");
        let authn_request = AuthnRequest {
            base: RequestBase {
                id: "_req_force_1".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: Some("https://idp.example.com/saml/sso".to_string()),
                consent: None,
                issuer: Some(Issuer::entity(entity_id)),
                has_signature: false,
            },
            subject: None,
            name_id_policy: None,
            conditions: None,
            requested_authn_context: None,
            scoping: None,
            force_authn: Some(force_authn),
            is_passive: None,
            assertion_consumer_service_index: None,
            assertion_consumer_service_url: Some("https://sp.example.com/acs".to_string()),
            protocol_binding: None,
            attribute_consuming_service_index: None,
            provider_name: None,
            extensions: None,
        };
        let saml_xml = authn_request
            .to_xml_string()
            .expect("serialize authn request");
        let params = RedirectEncodeParams {
            saml_xml: saml_xml.as_bytes(),
            is_request: true,
            destination: &destination,
            relay_state: None,
            signer: None,
        };
        redirect_encode(&params).expect("encode authn request")
    }

    #[tokio::test]
    async fn sso_rejects_force_authn_request() {
        let url = authn_request_url_with_force_authn("https://sp.example.com", "sp-1", true);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_to_string(resp).await;
        assert!(body.contains("fresh authentication required"));
    }

    #[tokio::test]
    async fn sso_allows_non_force_authn_request() {
        let url = authn_request_url_with_force_authn("https://sp.example.com", "sp-1", false);
        let state = test_state_full(
            Some(Ok(test_sp_client("https://sp.example.com"))),
            Some(Ok(session_with_email("alice@example.com"))),
            Some(Ok(active_idp_key())),
        );
        let req = sso_request(&url, vec![("X-Session-Token", "session-1")]);
        let resp = sso(State(state), Query(provider_query()), req)
            .await
            .expect("sso should succeed");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn authn_context_class_prefers_strongest_method() {
        let password = json!({"authentication_methods": [{"method": "password"}]});
        assert_eq!(
            authn_context_class_from_session(&password),
            constants::AUTHN_CONTEXT_PASSWORD
        );

        let totp = json!({"authentication_methods": [{"method": "password"}, {"method": "totp"}]});
        assert_eq!(
            authn_context_class_from_session(&totp),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
        );

        let webauthn = json!({"authentication_methods": [{"method": "webauthn"}]});
        assert_eq!(
            authn_context_class_from_session(&webauthn),
            constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
        );

        let empty = json!({});
        assert_eq!(
            authn_context_class_from_session(&empty),
            constants::AUTHN_CONTEXT_UNSPECIFIED
        );
    }
}
