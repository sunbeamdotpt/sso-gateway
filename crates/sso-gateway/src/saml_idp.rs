use std::collections::HashMap;
use std::sync::Arc;

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
use sso_ory_client::kratos::KratosClient;
use tracing::warn;

use crate::db::{SamlIdpKeyRepo, SamlSpClientRepo};

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

#[derive(Clone)]
pub struct SamlIdpState {
    pub kratos: Arc<KratosClient>,
    pub idp_keys: SamlIdpKeyRepo,
    pub sp_clients: SamlSpClientRepo,
    pub idp_entity_id: String,
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
        let params = url
            .split_once('?')
            .map(|(_, query)| parse_query_params(query))
            .unwrap_or_default();
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
            let value = parts.next().unwrap_or("");
            Some((key.to_string(), value.to_string()))
        })
        .collect()
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

    if sp_client.authn_requests_signed {
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

    let session_token = req
        .headers()
        .get("X-Session-Token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            SamlIdpError::Response(Box::new(idp_error(
                StatusCode::UNAUTHORIZED,
                "missing session",
            )))
        })?;

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
    let email = identity
        .get("traits")
        .and_then(|t| t.get("email"))
        .and_then(|v| v.as_str())
        .unwrap_or(identity_id);

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

    let options = ResponseOptions {
        idp_entity_id: state.idp_entity_id.clone(),
        in_response_to: Some(authn_request.base.id.clone()),
        sp_entity_id: sp_client.entity_id.clone(),
        acs_url: sp_client.acs_url.clone(),
        assertion_lifetime_seconds: 300,
        session_index: Some(identity_id.to_string()),
        session_not_on_or_after: None,
        authn_context_class_ref: Some(constants::AUTHN_CONTEXT_PASSWORD.to_string()),
        client_address: None,
        attributes: vec![Attribute {
            name: "email".to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![AttributeValue::String(email.to_string())],
        }],
    };
    let name_id = NameId {
        value: email.to_string(),
        format: sp_client.name_id_format.clone(),
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
    let relay_state = decoded.relay_state.unwrap_or_default();
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
    use http_body_util::BodyExt;

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
    fn response_signature_template_contains_reference() {
        let tpl = response_signature_template("_response_1");
        assert!(tpl.contains("URI=\"#_response_1\""));
        assert!(tpl.contains("rsa-sha256"));
    }
}
