use gamlastan::bindings::redirect::{RedirectEncodeParams, redirect_encode};
use gamlastan::bindings::relay_state::RelayState;
use gamlastan::core::assertion::issuer::Issuer;
use gamlastan::core::identifiers::SamlVersion;
use gamlastan::core::protocol::request::{AuthnRequest, RequestBase};
use gamlastan::xml::SamlSerialize;

use crate::harness::Gateway;

const NAME_ID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

#[tokio::test]
async fn saml_metadata_requires_provider_id() {
    let gateway = Gateway::start().await;

    let resp = gateway
        .http
        .get(format!("{}/saml/metadata", gateway.base_url))
        .send()
        .await
        .expect("metadata request should complete");

    assert!(
        resp.status().is_client_error(),
        "metadata endpoint must require provider_id"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn saml_metadata_returns_valid_sp_metadata() {
    let gateway = Gateway::start().await;
    let provider_id = gateway
        .create_saml_provider(
            "conformance-sp",
            "https://idp.example.com/entity",
            "https://idp.example.com/sso",
            None,
            "https://sp.example.com/entity",
            "https://sp.example.com/acs",
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
            "default",
            false,
        )
        .await;

    let resp = gateway
        .http
        .get(format!("{}/saml/metadata", gateway.base_url))
        .query(&[("provider_id", &provider_id)])
        .send()
        .await
        .expect("metadata request should succeed");

    assert!(resp.status().is_success(), "metadata request should succeed");
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("application/samlmetadata+xml")
    );

    let body = resp.text().await.expect("metadata should be text");
    assert!(
        body.contains("EntityDescriptor"),
        "metadata must contain an EntityDescriptor: {body}"
    );
    assert!(
        body.contains("SPSSODescriptor"),
        "metadata must contain an SPSSODescriptor"
    );
    assert!(
        body.contains("AssertionConsumerService"),
        "metadata must contain an AssertionConsumerService"
    );
    assert!(
        body.contains("https://sp.example.com/entity"),
        "metadata must contain the SP entity id"
    );
    assert!(
        body.contains("https://sp.example.com/acs"),
        "metadata must contain the ACS URL"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn saml_sso_returns_signed_response_html() {
    let gateway = Gateway::start().await;
    let (_key_id, _private_pem, _certificate_pem) = gateway.create_saml_idp_key().await;

    let entity_id = "https://sp.example.com/entity";
    let acs_url = "https://sp.example.com/acs";
    let provider_id = gateway
        .create_saml_sp_client(entity_id, acs_url, None, false, Some(NAME_ID_FORMAT))
        .await;

    let (_identity_id, session_token) = gateway.create_kratos_identity("saml-user@example.com").await;

    let url = build_authn_request_url(&gateway.base_url, &provider_id, entity_id, acs_url);

    let resp = gateway
        .http
        .get(url)
        .header("X-Session-Token", session_token)
        .send()
        .await
        .expect("sso request should succeed");

    assert!(
        resp.status().is_success(),
        "sso should return a successful html form: {:?}",
        resp.text().await.ok()
    );
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("text/html")
    );

    let body = resp.text().await.expect("sso body should be text");
    assert!(
        body.contains("SAMLResponse"),
        "sso response html must contain a SAMLResponse field"
    );
    assert!(
        body.contains(&html_escape(acs_url)),
        "sso response form must post to the configured ACS URL"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn saml_sso_rejects_missing_session_token() {
    let gateway = Gateway::start().await;
    let (_key_id, _private_pem, _certificate_pem) = gateway.create_saml_idp_key().await;

    let entity_id = "https://sp.example.com/entity";
    let acs_url = "https://sp.example.com/acs";
    let provider_id = gateway
        .create_saml_sp_client(entity_id, acs_url, None, false, Some(NAME_ID_FORMAT))
        .await;

    let url = build_authn_request_url(&gateway.base_url, &provider_id, entity_id, acs_url);

    let resp = gateway
        .http
        .get(url)
        .send()
        .await
        .expect("sso request should complete");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "sso must require a session token"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn saml_sso_rejects_malformed_authn_request() {
    let gateway = Gateway::start().await;
    let (_key_id, _private_pem, _certificate_pem) = gateway.create_saml_idp_key().await;

    let entity_id = "https://sp.example.com/entity";
    let acs_url = "https://sp.example.com/acs";
    let provider_id = gateway
        .create_saml_sp_client(entity_id, acs_url, None, false, Some(NAME_ID_FORMAT))
        .await;

    let (_identity_id, session_token) = gateway.create_kratos_identity("saml-user@example.com").await;

    let resp = gateway
        .http
        .get(format!("{}/saml/sso", gateway.base_url))
        .query(&[("provider_id", provider_id.as_str()), ("SAMLRequest", "not-valid-base64")])
        .header("X-Session-Token", session_token)
        .send()
        .await
        .expect("sso request should complete");

    assert!(
        resp.status().is_client_error(),
        "malformed SAMLRequest must be rejected"
    );

    gateway.shutdown().await;
}

fn build_authn_request_url(
    base_url: &str,
    provider_id: &str,
    entity_id: &str,
    acs_url: &str,
) -> String {
    let authn_request = AuthnRequest {
        base: RequestBase {
            id: "_conformance_req_1".to_string(),
            version: SamlVersion::V2_0,
            issue_instant: chrono::Utc::now(),
            destination: None,
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
        assertion_consumer_service_url: Some(acs_url.to_string()),
        protocol_binding: None,
        attribute_consuming_service_index: None,
        provider_name: None,
        extensions: None,
    };

    let saml_xml = authn_request
        .to_xml_string()
        .expect("authn request should serialize");
    let destination = format!("{base_url}/saml/sso?provider_id={provider_id}");
    let relay_state = RelayState::new("conformance-state").ok();
    let params = RedirectEncodeParams {
        saml_xml: saml_xml.as_bytes(),
        is_request: true,
        destination: &destination,
        relay_state: relay_state.as_ref(),
        signer: None,
    };

    redirect_encode(&params).expect("authn request should encode")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('\'', "&#x27;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
